package des_cfb

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/wzshiming/shadowsocks/stream"
)

func init() {
	stream.RegisterCipher("des-cfb", 8, 8, NewDESStreamEncrypt, NewDESStreamDecrypt)
}

func NewDESStreamEncrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func NewDESStreamDecrypt(key, iv []byte) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}
