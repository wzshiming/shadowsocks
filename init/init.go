package init

import (
	_ "github.com/wzshiming/shadowsocks/aead/aes-x-gcm"
	_ "github.com/wzshiming/shadowsocks/aead/chacha20-ietf-poly1305"
	_ "github.com/wzshiming/shadowsocks/stream/aes-x-cfb"
	_ "github.com/wzshiming/shadowsocks/stream/aes-x-ctr"
	_ "github.com/wzshiming/shadowsocks/stream/bf-cfb"
	_ "github.com/wzshiming/shadowsocks/stream/cast5-cfb"
	_ "github.com/wzshiming/shadowsocks/stream/chacha20"
	_ "github.com/wzshiming/shadowsocks/stream/des-cfb"
	_ "github.com/wzshiming/shadowsocks/stream/rc4-md5-x"
	_ "github.com/wzshiming/shadowsocks/stream/salsa20"
)
