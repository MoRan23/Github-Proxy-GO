FROM registry.cn-hangzhou.aliyuncs.com/moran233/nn:golang-1.23.2-alpine AS builder

WORKDIR /app
COPY . .

RUN go mod init github.com/MoRan23/Github-Proxy-GO && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o github-proxy .

FROM registry.cn-hangzhou.aliyuncs.com/moran233/nn:alpine

WORKDIR /app
COPY --from=builder /app/github-proxy /app/github-proxy

EXPOSE 80

CMD ["/app/github-proxy"]