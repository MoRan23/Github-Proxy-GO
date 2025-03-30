# Github-Proxy-GO

[gh-proxy](https://github.com/hunshcn/gh-proxy) 项目的Go版本实现。  
占用更小的存储，Docker镜像仅8MB。

## 使用方法
大致使用方法与原项目一致，可以查看原项目，这里只列出Go版本的有变更的地方。  
### 删减
+ `jsdelivr` 配置项删除了，完全由服务器代理。
+ `pass_list` 也删除了
### 修改
+ 过大的请求将会重定向直连，防止服务器占用资源过大。
+ 默认请求大小限制为1GB。
+ 黑白名单设置分隔符由`\n`改为`,`。
### 新增
+ 配置项可通过环境变量设置
+ 身份认证功能
+ 可修改入口点
### 配置
+ `WHITE_LIST` 白名单 (eg: `user1,user1/repo,*/repo1`)
+ `BLACK_LIST` 黑名单 (eg: `user1/repo,*/repo1`)  
> [!IMPORTANT]  
>   生效顺序 白->黑
+ `USER` 用户名 (eg: `user`)
+ `PASSWORD` 密码 (eg: `pass`)  
> [!INFO]  
>   防止被蹭，身份认证为必须项。  
>   认证头为 `X-My-Auth`, 值为 `Basic base64(USER:PASSWORD)`  
>   使用方法为:  
>   ```shell
>   # 单次  
>   git -c http.extraHeader="X-My-Auth: Basic YWE6YWE=" clone https://domain/https://github.com/xx/xx.git  
>   # 永久  
>   git config --global http.extraHeader "X-My-Auth: Basic YWE6YWE="
> ```
+ `ENTRY` 入口 `uri`, 默认为 `/` (eg: `test`) 此时入口为 `/test/`
### 部署
#### Docker
```shell
docker run -d -p 7888:80 -e USER=user -e PASSWORD=pass --name "githubProxy" registry.cn-hangzhou.aliyuncs.com/moran233/github-proxy-go:latest
```
#### 本地
```shell
USER=user PASSWORD=pass Github-Proxy-GO
```