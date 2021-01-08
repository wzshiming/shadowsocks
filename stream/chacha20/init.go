package chacha20

import (
	"crypto/cipher"

	"github.com/aead/chacha20"
	"github.com/wzshiming/shadowsocks/stream"
)

func init() {
	stream.RegisterCipher("chacha20", 32, 8, NewChaCha20Stream, NewChaCha20Stream)
	stream.RegisterCipher("chacha20-ietf", 32, 12, NewChaCha20Stream, NewChaCha20Stream)
}

func NewChaCha20Stream(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}
