package blake3_chacha20_poly1305

import (
	"github.com/wzshiming/shadowsocks/aead2022"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	// UDP packets are sealed with XChaCha20-Poly1305.
	aead2022.RegisterPacketAEADCipher("2022-blake3-chacha20-poly1305", 32, chacha20poly1305.New, chacha20poly1305.NewX)
}
