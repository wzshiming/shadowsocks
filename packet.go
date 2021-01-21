package shadowsocks

import (
	"bytes"
	"context"
	"net"
)

type ListenPacket interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

func decryptPacket(c ConnCipher, p BytesPool, dist, src []byte) (n int, addr net.Addr, err error) {
	i, err := c.Decrypt(dist, src)
	if err != nil {
		return 0, nil, err
	}
	buf := bytes.NewBuffer(dist[:i])
	a, err := readAddress(buf)
	if err != nil {
		return 0, nil, err
	}
	i = copy(dist, buf.Bytes())
	return i, a, nil
}

func encryptPacket(c ConnCipher, p BytesPool, dist, src []byte, addr net.Addr) (n int, err error) {
	a, err := parseAddress(addr.String())
	if err != nil {
		return 0, err
	}
	buf := getBytes(p)
	defer putBytes(p, buf)
	b := bytes.NewBuffer(buf[:0])
	err = writeAddress(b, a)
	if err != nil {
		return 0, err
	}
	b.Write(src)
	i, err := c.Encrypt(dist, b.Bytes())
	if err != nil {
		return 0, err
	}
	return i, nil
}

func toUDPAddr(addr net.Addr) (net.Addr, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return addr, nil
	case *address:
		return &net.UDPAddr{
			IP:   a.IP,
			Port: a.Port,
		}, nil
	default:
		a, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return nil, err
		}
		return a, nil
	}
}
