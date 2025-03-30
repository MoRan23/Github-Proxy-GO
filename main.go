package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// 配置常量
const (
	chunkSize     = 10240 // 10KB 块大小
	defaultListen = ":80" // 默认监听地址
	maxSizeGB     = 999
)

var (
	// 正则表达式匹配 GitHub URL 模式
	exp1 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$`)
	exp2 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$`)
	exp3 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$`)
	exp4 = regexp.MustCompile(`^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$`)
	exp5 = regexp.MustCompile(`^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$`)

	// 认证配置
	authUsername string
	authPassword string
	//requireAuth  = true
	entry = "/"

	// 黑白名单
	whiteList []tuple
	blackList []tuple
	passList  []tuple

	jsdelivr  = 0       // 是否使用 jsDelivr 镜像
	sizeLimit = 1 << 30 // 1GB 文件大小限制

	// 缓存正则匹配结果
	regexCache = sync.Map{}
)

type tuple struct {
	user string
	repo string
}

func init() {
	// 初始化黑白名单 (可以从环境变量或配置文件加载)
	whiteList = parseList(os.Getenv("WHITE_LIST"))
	blackList = parseList(os.Getenv("BLACK_LIST"))
	passList = parseList(os.Getenv("PASS_LIST"))
	fmt.Printf("Set White_List: %v\nSet Black_List: %v\nSet Pass_List: %v\n", whiteList, blackList, passList)
	// 初始化认证配置
	authUsername = os.Getenv("USER")
	authPassword = os.Getenv("PASSWORD")
	if authUsername == "" || authPassword == "" {
		log.Fatal("USER or PASSWORD is empty")
	}
	fmt.Printf("Set User: %s\nSet Password: %s\n", authUsername, authPassword)
	// 初始化 jsDelivr 配置
	if os.Getenv("JSDelivr") == "1" {
		jsdelivr = 1
	}
	fmt.Printf("Set jsdelivr: %d\n", jsdelivr)
	// 从环境变量读取文件大小限制，默认 1GB (1 << 30)
	if envSize := os.Getenv("SIZE_LIMIT"); envSize != "" {
		parsed, err := ParseSimpleSize(envSize)
		if err != nil {
			fmt.Printf("Error parsing SIZE_LIMIT: %v\n", err)
			fmt.Printf("Using default size limit: %d bytes (1GB)\n", sizeLimit)
			return
		}
		sizeLimit = parsed
	}
	fmt.Printf("Size limit set to %d bytes\n", sizeLimit)
	// 入口端点设置
	if os.Getenv("ENTRY") != "" {
		entry = "/" + os.Getenv("ENTRY") + "/"
	}
	fmt.Printf("Set Entry: %s\n", entry)
}

func main() {
	http.HandleFunc(entry, authMiddleware(proxyHandler))

	log.Printf("Starting server on %s\n", defaultListen)
	if err := http.ListenAndServe(defaultListen, nil); err != nil {
		log.Fatalf("Server failed: %v\n", err)
	}
}

// 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//if !requireAuth {
		//	next(w, r)
		//	return
		//}

		authHeader := r.Header.Get("X-My-Auth")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Login Required"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		authParts := strings.SplitN(authHeader, " ", 2)
		if len(authParts) != 2 || authParts[0] != "Basic" {
			http.Error(w, "Invalid authentication", http.StatusUnauthorized)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(authParts[1])
		if err != nil {
			http.Error(w, "Invalid authentication", http.StatusUnauthorized)
			return
		}

		creds := strings.SplitN(string(decoded), ":", 2)
		if len(creds) != 2 || creds[0] != authUsername || creds[1] != authPassword {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// 主代理处理函数
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimPrefix(r.URL.Path, entry)
	if !strings.HasPrefix(u, "http") {
		u = "https://" + u
	}

	// 修复 URL 格式
	if strings.Index(u[3:], "://") == -1 {
		u = strings.Replace(u, "s:/", "s://", 1)
	}

	passBy := false
	m := checkURL(u)
	if m != nil {
		t := tuple{m[1], m[2]}

		// 检查白名单
		if len(whiteList) > 0 {
			allowed := false
			for _, item := range whiteList {
				if matchTuple(t, item) {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "Forbidden by white list", http.StatusForbidden)
				return
			}
		}

		// 检查黑名单
		for _, item := range blackList {
			if matchTuple(t, item) {
				http.Error(w, "Forbidden by black list", http.StatusForbidden)
				return
			}
		}

		// 检查直通名单
		for _, item := range passList {
			if matchTuple(t, item) {
				passBy = true
				break
			}
		}
	} else {
		http.Error(w, "Invalid input", http.StatusForbidden)
		return
	}

	// 处理 jsDelivr 重定向
	if (jsdelivr != 0 || passBy) && exp2.MatchString(u) {
		newURL := strings.Replace(u, "/blob/", "@", 1)
		newURL = strings.Replace(newURL, "github.com", "cdn.jsdelivr.net/gh", 1)
		http.Redirect(w, r, newURL, http.StatusFound)
		return
	} else if (jsdelivr != 0 || passBy) && exp4.MatchString(u) {
		newURL := regexp.MustCompile(`(\.com/.*?/.+?)/(.+?/)`).ReplaceAllString(u, "${1}@${2}")
		if strings.Contains(newURL, "raw.githubusercontent.com") {
			newURL = strings.Replace(newURL, "raw.githubusercontent.com", "cdn.jsdelivr.net/gh", 1)
		} else {
			newURL = strings.Replace(newURL, "raw.github.com", "cdn.jsdelivr.net/gh", 1)
		}
		http.Redirect(w, r, newURL, http.StatusFound)
		return
	}

	// 处理原始代理请求
	if exp2.MatchString(u) {
		u = strings.Replace(u, "/blob/", "/raw/", 1)
	}

	if passBy {
		newURL := u + strings.TrimPrefix(r.URL.String(), r.URL.Path)
		if strings.HasPrefix(newURL, "https:/") && !strings.HasPrefix(newURL, "https://") {
			newURL = "https://" + newURL[7:]
		}
		http.Redirect(w, r, newURL, http.StatusFound)
		return
	}

	// URL 编码并代理
	escapedURL, _ := url.PathUnescape(u)
	proxyRequest(w, r, escapedURL, false)
}

// 代理请求
func proxyRequest(w http.ResponseWriter, r *http.Request, targetURL string, allowRedirects bool) {
	// 构建目标 URL
	fullURL := targetURL + strings.TrimPrefix(r.URL.String(), r.URL.Path)
	if strings.HasPrefix(fullURL, "https:/") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "https://" + fullURL[7:]
	}

	// 创建新请求
	req, err := http.NewRequest(r.Method, fullURL, r.Body)
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for k, v := range r.Header {
		if k != "Host" && k != "X-My-Auth" {
			req.Header[k] = v
		}
	}

	// 发送请求aa
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if allowRedirects {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 检查文件大小
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if size, err := fmt.Sscanf(contentLength, "%d", new(int)); err == nil && size > sizeLimit {
			http.Redirect(w, r, fullURL, http.StatusFound)
			return
		}
	}

	// 处理重定向
	if location := resp.Header.Get("Location"); location != "" {
		if checkURL(location) != nil {
			resp.Header.Set("Location", "/"+location)
		} else {
			proxyRequest(w, r, location, true)
			return
		}
	}

	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// 设置状态码
	w.WriteHeader(resp.StatusCode)

	// 流式传输响应体
	buf := make([]byte, chunkSize)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				log.Printf("Error writing response: %v", err)
				break
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading response: %v", err)
			break
		}
	}
}

// CheckURL 检查 URL 是否匹配 GitHub 模式
func checkURL(u string) []string {
	// 先查缓存
	if cached, ok := regexCache.Load(u); ok {
		return cached.([]string) // 直接返回缓存结果
	}

	// 缓存未命中，执行正则匹配
	for _, exp := range []*regexp.Regexp{exp1, exp2, exp3, exp4, exp5} {
		if matches := exp.FindStringSubmatch(u); matches != nil {
			regexCache.Store(u, matches) // 存入缓存
			return matches
		}
	}

	regexCache.Store(u, nil) // 即使未匹配也缓存，避免后续重复计算
	return nil
}

// 检查元组是否匹配
func matchTuple(target, pattern tuple) bool {
	if pattern.user == "*" {
		return target.repo == pattern.repo
	}
	if pattern.repo == "*" {
		return target.user == pattern.user
	}
	return target.user == pattern.user && target.repo == pattern.repo
}

// 解析列表字符串
func parseList(listStr string) []tuple {
	var result []tuple
	lines := strings.Split(listStr, ",")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) == 1 {
			result = append(result, tuple{user: parts[0], repo: "*"})
		} else if len(parts) == 2 {
			result = append(result, tuple{user: parts[0], repo: parts[1]})
		}
	}
	return result
}

// ParseSimpleSize 解析简化的容量字符串（支持 M/G 单位），最大限制 999GB
func ParseSimpleSize(sizeStr string) (int, error) {
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
