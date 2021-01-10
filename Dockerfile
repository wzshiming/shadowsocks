FROM golang:alpine AS builder
WORKDIR /go/src/github.com/wzshiming/shadowsocks/
COPY . .
ENV CGO_ENABLED=0
RUN go install ./cmd/shadowsocks

FROM alpine
EXPOSE 8379
COPY --from=builder /go/bin/shadowsocks /usr/local/bin/
ENTRYPOINT [ "/usr/local/bin/shadowsocks" ]
