package aes_x_cfb

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/wzshiming/shadowsocks/stream"
)

func init() {
	stream.RegisterCipher("aes-128-cfb", 16, 16, NewAESCFBStreamEncrypt, NewAESCFBStreamDecrypt)
	stream.RegisterCipher("aes-192-cfb", 24, 16, NewAESCFBStreamEncrypt, NewAESCFBStreamDecrypt)
	stream.RegisterCipher("aes-256-cfb", 32, 16, NewAESCFBStreamEncrypt, NewAESCFBStreamDecrypt)
}

func NewAESCFBStreamEncrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func NewAESCFBStreamDecrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}
