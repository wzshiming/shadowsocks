package dummy

import (
	"net"

	"github.com/wzshiming/shadowsocks"
)

func init() {
	shadowsocks.RegisterCipher("dummy", func(password string) (shadowsocks.ConnCipher, error) {
		return &cipher{}, nil
	})
}

type cipher struct {
}

func (cipher) StreamConn(conn net.Conn) net.Conn {
	return conn
}

func (cipher) Decrypt(dist, src []byte) (n int, err error) {
	return copy(dist, src), nil
}
func (cipher) Encrypt(dist, src []byte) (n int, err error) {
	return copy(dist, src), nil
}
