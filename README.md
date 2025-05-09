# Github-Proxy-GO

[gh-proxy](https://github.com/hunshcn/gh-proxy) 项目的Go版本实现。  
占用更小的存储，Docker镜像仅8MB。

## 使用方法
大致使用方法与原项目一致，可以查看原项目，这里只列出Go版本的有变更的地方。  
### 删减
+ `jsdelivr` 配置项删除了，完全由服务器代理。
+ `pass_list` 也删除了
+ 前端页面删除了，只保留了代理功能。
### 修改
+ 过大的请求将会重定向直连，防止服务器占用资源过大。
+ 默认请求大小限制为1GB。
+ 黑白名单设置分隔符由`\n`改为`,`。
### 新增
+ 配置项可通过环境变量设置
+ 身份认证功能
+ 可修改入口点
+ 随机路径认证方式
### 配置
+ `WHITE_LIST` 白名单 (eg: `user1,user1/repo,*/repo1`)
+ `BLACK_LIST` 黑名单 (eg: `user1/repo,*/repo1`)  
> [!TIP]  
>   生效顺序 白->黑
+ `USER` 用户名 (eg: `user`)
+ `PASSWORD` 密码 (eg: `pass`)  
> [!TIP]  
>   防止被蹭，身份认证为必须项。  
>   认证头为 `X-My-Auth`, 值为 `md5(USER:PASSWORD)`  
>   使用方法为(用户名密码均为`aa`):  
>   ```shell
>   # 单次  
>   git -c http.extraHeader="X-My-Auth: 8d5f6caa25c00067ead4478915b7ef00" clone https://domain/https://github.com/xx/xx.git  
>   # 永久  
>   git config --global http.extraHeader "X-My-Auth: 8d5f6caa25c00067ead4478915b7ef00"
> ```
+ `ENTRY` 入口 `uri`, 默认为 `/` (eg: `test`) 此时入口为 `/test/`
+ `SIZE_LIMIT` 请求大小限制，最小单位到MB，最大单位到GB (eg: `1G` 或 `10M` 或 `1G10M`)
+ `RAND_ENTRY` 随机路径认证方式开关，`ON`为开启，其他为关闭 (eg: `ON`)
### 部署
#### Docker
```shell
docker run -d -p 7888:80 -e USER=user -e PASSWORD=pass --name "githubProxy" registry.cn-hangzhou.aliyuncs.com/moran233/github-proxy-go:latest
```
#### 本地
```shell
USER=user PASSWORD=pass Github-Proxy-GO
```
### 更新
#### 2025-4-2
+ 添加一个随机值的路径(需通过配置`RAND_ENTRY`环境变量为`ON`开启)，该路径通过`随机路径+md5(USER:PASSWORD)`进行身份认证，无法自己设置，将由程序自动生成，可查看日志获取。
> [!TIP]  
>   例如生成的随机路径为`/aabb/`, 用户名为`aa`, 密码为`bb`
>   则认证路径为`/aabb/3a2f6b6d8b508509996c50df7031e53d/https://github.com/xxx`
+ 普通身份认证方式也修改为`md5`加密，不再使用`base64`加密。