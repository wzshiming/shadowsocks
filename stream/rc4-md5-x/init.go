package rc4_md5_x

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"

	"github.com/wzshiming/shadowsocks/stream"
)

func init() {
	stream.RegisterCipher("rc4-md5", 16, 16, NewRC4MD5Stream, NewRC4MD5Stream)
	stream.RegisterCipher("rc4-md5-6", 16, 6, NewRC4MD5Stream, NewRC4MD5Stream)
}

func NewRC4MD5Stream(key, iv []byte) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)
	return rc4.NewCipher(rc4key)
}
