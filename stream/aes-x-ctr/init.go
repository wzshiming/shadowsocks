package aes_x_ctr

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/wzshiming/shadowsocks/stream"
)

func init() {
	stream.RegisterCipher("aes-128-ctr", 16, 16, NewAESCTRStream, NewAESCTRStream)
	stream.RegisterCipher("aes-192-ctr", 24, 16, NewAESCTRStream, NewAESCTRStream)
	stream.RegisterCipher("aes-256-ctr", 32, 16, NewAESCTRStream, NewAESCTRStream)
}

func NewAESCTRStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}
