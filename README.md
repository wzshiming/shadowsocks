# ShadowSocks

ShadowSocks server and client

[![Build](https://github.com/wzshiming/shadowsocks/actions/workflows/go-cross-build.yml/badge.svg)](https://github.com/wzshiming/shadowsocks/actions/workflows/go-cross-build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/wzshiming/shadowsocks)](https://goreportcard.com/report/github.com/wzshiming/shadowsocks)
[![GoDoc](https://godoc.org/github.com/wzshiming/shadowsocks?status.svg)](https://godoc.org/github.com/wzshiming/shadowsocks)
[![GitHub license](https://img.shields.io/github/license/wzshiming/shadowsocks.svg)](https://github.com/wzshiming/shadowsocks/blob/master/LICENSE)
[![gocover.io](https://gocover.io/_badge/github.com/wzshiming/shadowsocks)](https://gocover.io/github.com/wzshiming/shadowsocks)

This project is to add protocol support for the [Bridge](https://github.com/wzshiming/bridge), or it can be used alone

The following is the implementation of other proxy protocols

- [Socks4](https://github.com/wzshiming/socks4)
- [Socks5](https://github.com/wzshiming/socks5)
- [HTTP Proxy](https://github.com/wzshiming/httpproxy)
- [SSH Proxy](https://github.com/wzshiming/sshproxy)

## Usage

[API Documentation](https://godoc.org/github.com/wzshiming/shadowsocks)

[Example](https://github.com/wzshiming/shadowsocks/blob/master/cmd/shadowsocks/main.go)

## Features

- [x] Support TCP proxy
- [x] Support UDP proxy

## Encrypto method

- AEAD
  - [x] aes-128-gcm
  - [x] aes-256-gcm
  - [x] chacha20-ietf-poly1305
- Stream
  - [x] aes-128-cfb
  - [x] aes-192-cfb
  - [x] aes-256-cfb
  - [x] aes-128-ctr
  - [x] aes-192-ctr
  - [x] aes-256-ctr
  - [x] des-cfb
  - [x] bf-cfb
  - [x] cast5-cfb
  - [x] rc4-md5
  - [x] chacha20
  - [x] chacha20-ietf
  - [x] salsa20

## License

Licensed under the MIT License. See [LICENSE](https://github.com/wzshiming/shadowsocks/blob/master/LICENSE) for the full license text.
