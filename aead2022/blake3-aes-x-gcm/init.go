package blake3_aes_x_gcm

import (
	"crypto/aes"

	aes_x_gcm "github.com/wzshiming/shadowsocks/aead/aes-x-gcm"
	"github.com/wzshiming/shadowsocks/aead2022"
)

func init() {
	aead2022.RegisterCipher("2022-blake3-aes-128-gcm", 16, aes_x_gcm.NewAESGCM, aes.NewCipher)
	aead2022.RegisterCipher("2022-blake3-aes-256-gcm", 32, aes_x_gcm.NewAESGCM, aes.NewCipher)
}
