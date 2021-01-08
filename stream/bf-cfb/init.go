package bf_cfb

import (
	"crypto/cipher"

	"github.com/wzshiming/shadowsocks/stream"
	"golang.org/x/crypto/blowfish"
)

func init() {
	stream.RegisterCipher("bf-cfb", 16, 8, NewBlowFishStreamEncrypt, NewBlowFishStreamDecrypt)
}

func NewBlowFishStreamEncrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func NewBlowFishStreamDecrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}
