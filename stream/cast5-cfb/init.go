package cast5_cfb

import (
	"crypto/cipher"

	"github.com/wzshiming/shadowsocks/stream"
	"golang.org/x/crypto/cast5"
)

func init() {
	stream.RegisterCipher("cast5-cfb", 16, 8, NewCast5StreamEncrypt, NewCast5StreamDecrypt)
}

func NewCast5StreamEncrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func NewCast5StreamDecrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}
