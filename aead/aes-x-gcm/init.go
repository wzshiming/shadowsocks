package aes_x_gcm

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/wzshiming/shadowsocks/aead"
)

func init() {
	aead.RegisterCipher("aes-128-gcm", 16, NewAESGCM)
	aead.RegisterCipher("aes-192-gcm", 24, NewAESGCM)
	aead.RegisterCipher("aes-256-gcm", 32, NewAESGCM)
}

func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
