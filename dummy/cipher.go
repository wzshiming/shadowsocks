package dummy

import (
	"net"

	"github.com/wzshiming/shadowsocks"
	"github.com/wzshiming/shadowsocks/internal/socks"
)

func init() {
	shadowsocks.RegisterCipher("dummy", func(password string) (shadowsocks.Cipher, error) {
		return cipher{}, nil
	})
}

type cipher struct {
}

func (cipher) ClientConn(conn net.Conn, target *shadowsocks.Addr) (net.Conn, error) {
	addr, err := socks.AppendAddr(nil, target)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(addr); err != nil {
		return nil, err
	}
	return conn, nil
}

func (cipher) ServerConn(conn net.Conn) (net.Conn, *shadowsocks.Addr, error) {
	target, err := socks.ReadAddr(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, target, nil
}

func (c cipher) ClientPacket() (shadowsocks.PacketSession, error) {
	return c, nil
}

func (c cipher) ServerPacket(dist, src []byte) (n int, reply shadowsocks.PacketEncrypter, err error) {
	return copy(dist, src), c, nil
}

func (cipher) Decrypt(dist, src []byte) (n int, err error) {
	return copy(dist, src), nil
}

func (cipher) Encrypt(dist, src []byte) (n int, err error) {
	return copy(dist, src), nil
}
