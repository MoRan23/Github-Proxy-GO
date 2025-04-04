package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	PORT = ":80" // 监听端口

	CHUNK_SIZE = 1024 * 10 // 分块大小
)

var (
	// 编译正则表达式
	exp1 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$`)
	exp2 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$`)
	exp3 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$`)
	exp4 = regexp.MustCompile(`^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$`)
	exp5 = regexp.MustCompile(`^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$`)

	regexpList = []*regexp.Regexp{exp1, exp2, exp3, exp4, exp5}

	whiteList = parseList(``)
	blackList = parseList(``)

	AUTH_USERNAME string // 认证用户名
	AUTH_PASSWORD string // 认证密码
	AUTH_MD5_HASH string // 认证密码的 MD5 哈希
	// REQUIRE_AUTH  = true                     // 是否启用认证
	entry      = "/"
	rEntry     string
	rEntryOpen string
	fileName   = "rEntry"

	SIZE_LIMIT = 1024 * 1024 * 1024 // 允许的文件大小，默认999GB
	maxSizeGB  = 999                // 最大文件大小限制
)

type ListItem struct {
	Author string
	Repo   string
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func init() {
	// 初始化黑白名单 (可以从环境变量或配置文件加载)
	whiteList = parseList(os.Getenv("WHITE_LIST"))
	blackList = parseList(os.Getenv("BLACK_LIST"))
	fmt.Printf("Set White_List: %v\nSet Black_List: %v\n", whiteList, blackList)
	// 初始化认证配置
	AUTH_USERNAME = os.Getenv("USER")
	AUTH_PASSWORD = os.Getenv("PASSWORD")
	if AUTH_PASSWORD == "" || AUTH_USERNAME == "" {
		log.Fatal("USER or PASSWORD is empty")
	}
	fmt.Printf("Set User: %s\nSet Password: %s\n", AUTH_USERNAME, AUTH_PASSWORD)
	hasher := md5.New()
	hasher.Write([]byte(AUTH_USERNAME + ":" + AUTH_PASSWORD))
	AUTH_MD5_HASH = hex.EncodeToString(hasher.Sum(nil))
	// 从环境变量读取文件大小限制，默认 1GB (1 << 30)
	if envSize := os.Getenv("SIZE_LIMIT"); envSize != "" {
		parsed, err := parseSimpleSize(envSize)
		if err != nil {
			fmt.Printf("Error parsing SIZE_LIMIT: %v\n", err)
			fmt.Printf("Using default size limit: %d bytes (1GB)\n", SIZE_LIMIT)
			return
		}
		SIZE_LIMIT = parsed
	}
	fmt.Printf("Size limit set to %d bytes\n", SIZE_LIMIT)
	// 入口端点设置
	if os.Getenv("ENTRY") != "" {
		entry = "/" + os.Getenv("ENTRY") + "/"
	}
	fmt.Printf("Set Entry: %s\n", entry)
	// 尝试从文件中读取入口
	rEntryOpen = os.Getenv("RAND_ENTRY")
	if rEntryOpen == "ON" {
		data, err := os.ReadFile(fileName)
		if err == nil && len(data) > 0 {
			// 文件存在，读取入口
			rEntry = string(data)
			fmt.Printf("Set Random Entry: %s\n", rEntry)
		} else {
			// 文件不存在或为空，创建新的随机入口
			rEntry = "/" + randomString(10) + "/"
			fmt.Printf("Set Random Entry: %s\n", rEntry)

			// 将新入口写入文件
			err = os.WriteFile(fileName, []byte(rEntry), 0644)
			if err != nil {
				panic(err)
			}
		}
	}
}

func main() {
	http.HandleFunc(entry, authMiddleware(proxyGHHandle))
	if rEntryOpen == "ON" {
		http.HandleFunc(rEntry, proxyGHHandle)
	}

	log.Printf("Starting server on %s\n", PORT)
	if err := http.ListenAndServe(PORT, nil); err != nil {
		log.Fatalf("Server failed: %v\n", err)
	}
}

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//if !REQUIRE_AUTH {
		//	next(w, r)
		//	return
		//}

		auth := r.Header.Get("X-My-Auth")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Login Required\"")
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		if !md5Auth(auth) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func md5Auth(encode string) bool {
	return encode == AUTH_MD5_HASH
}

// 处理代理请求
func proxyGHHandle(w http.ResponseWriter, r *http.Request) {
	// /https://github.com/..... -> https://github.com/.....
	var urlStr string
	if rEntryOpen == "ON" && strings.HasPrefix(r.URL.Path, rEntry) {
		urlStr = strings.TrimPrefix(r.URL.Path, rEntry)
		// 提取第一个 `/` 之前的字符串
		firstSlashIndex := strings.Index(urlStr, "/")
		if firstSlashIndex != -1 {
			// 获取第一个 `/` 之前的部分
			beforeFirstSlash := urlStr[:firstSlashIndex]

			// 进行 MD5 认证
			if !md5Auth(beforeFirstSlash) {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}
		} else {
			http.Error(w, "Invalid input.", http.StatusForbidden)
			return
		}
		urlStr = strings.TrimPrefix(urlStr, AUTH_MD5_HASH+"/")
	} else {
		urlStr = strings.TrimPrefix(r.URL.Path, entry)
	}
	// 如果不是以http开头，则添加https
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://" + urlStr
	}

	// 修复URL格式
	if strings.Index(urlStr, "://") == -1 {
		urlStr = strings.Replace(urlStr, "s:/", "s://", 1)
	}

	// 检查URL是否匹配GitHub格式
	// author: 作者
	// repo: 仓库
	// valid: 是否匹配
	author, repo, valid := checkURL(urlStr)
	if !valid {
		http.Error(w, "Invalid input.", http.StatusForbidden)
		return
	}

	// 白名单检查
	if len(whiteList) > 0 {
		if !matchListItem(author, repo, whiteList) {
			http.Error(w, "Forbidden by white list.", http.StatusForbidden)
			return
		}
	}

	// 黑名单检查
	if matchListItem(author, repo, blackList) {
		http.Error(w, "Forbidden by black list.", http.StatusForbidden)
		return
	}

	if exp2.MatchString(urlStr) {
		urlStr = strings.Replace(urlStr, "/blob/", "/raw/", 1)
	}

	// 代理请求
	proxyRequest(urlStr, w, r)

}

// 执行代理请求
func proxyRequest(targetURL string, w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	// 解析目标 URL（targetURL 应为完整 URL，如 "https://example.com/path"）
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Server error: "+err.Error(), http.StatusInternalServerError)
		// 处理解析错误（如 targetURL 格式无效）
		return
	}

	// 合并原始请求的查询参数到目标 URL
	if r.URL.RawQuery != "" {
		// 解析原始请求的查询参数
		sourceQuery := r.URL.Query()

		// 合并到目标 URL 的查询参数（同名参数会被覆盖）
		targetQuery := target.Query()
		for key, values := range sourceQuery {
			targetQuery[key] = values // 保留原始值的切片
		}

		// 重新编码查询参数
		target.RawQuery = targetQuery.Encode()
	}

	// 生成最终完整 URL（自动处理协议、路径和编码）
	fullURL := target.String()
	queryStr := target.RawQuery

	fmt.Println("Fetch:", fullURL)

	// 创建请求
	req, err := http.NewRequest(r.Method, fullURL, r.Body)
	if err != nil {
		http.Error(w, "Server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 检查内容长度是否超过限制
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if length, err := fmt.Sscanf(contentLength, "%d"); err == nil && length > SIZE_LIMIT {
			http.Redirect(w, r, targetURL+"?"+queryStr, http.StatusFound)
			return
		}
	}

	// 处理重定向
	if location := resp.Header.Get("Location"); location != "" {
		_, _, valid := checkURL(location)
		if valid {
			w.Header().Set("Location", entry+location)
		} else {
			proxyRequest(location, w, r)
			return
		}
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			if key == "Location" {
				continue
			}
			w.Header().Add(key, value)
		}
	}

	// 设置状态码
	w.WriteHeader(resp.StatusCode)

	// 分块传输响应体
	buf := make([]byte, CHUNK_SIZE)
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}
	for {
		n, err := resp.Body.Read(buf)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}

		if _, err := w.Write(buf[:n]); err != nil {
			break
		}

		f.Flush()

		if err == io.EOF {
			break
		}
	}
}

// 检查URL是否匹配GitHub格式
func checkURL(u string) (string, string, bool) {
	for _, exp := range regexpList {
		matches := exp.FindStringSubmatch(u)
		if len(matches) > 2 {
			return matches[1], matches[2], true
		}
	}
	return "", "", false
}

// 检查是否匹配列表项
func matchListItem(author, repo string, list []ListItem) bool {
	for _, item := range list {
		if (item.Author == "*" && item.Repo == repo) ||
			(item.Author == author && item.Repo == "") ||
			(item.Author == author && item.Repo == repo) {
			return true
		}
	}
	return false
}

// 解析列表配置
func parseList(list string) []ListItem {
	var result []ListItem
	lines := strings.Split(list, ",")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) == 1 {
			result = append(result, ListItem{
				Author: strings.TrimSpace(parts[0]),
				Repo:   "",
			})
		} else if len(parts) >= 2 {
			result = append(result, ListItem{
				Author: strings.TrimSpace(parts[0]),
				Repo:   strings.TrimSpace(parts[1]),
			})
		}
	}
	return result
}

// 解析简化的容量字符串（支持 M/G 单位），最大限制 999GB
func parseSimpleSize(sizeStr string) (int, error) {
	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return 0, nil
	}

	// 正则匹配 数字+单位 的组合（如 3M, 2G, 1G512M）
	re := regexp.MustCompile(`(\d+)([GM])`)
	matches := re.FindAllStringSubmatch(sizeStr, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("invalid size format: %s", sizeStr)
	}

	var totalMB int // 用MB作为中间单位计算
	for _, match := range matches {
		num, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, fmt.Errorf("invalid number: %s", match[1])
		}

		switch match[2] {
		case "G":
			totalMB += num * 1024
		case "M":
			totalMB += num
		}
	}

	// 自动限制最大值
	if totalMB > maxSizeGB*1024 {
		totalMB = maxSizeGB * 1024
	}

	return totalMB * 1024 * 1024, nil // 转换为字节
}
