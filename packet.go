package shadowsocks

import (
	"bytes"
	"context"
	"fmt"
	"net"
)

type ListenPacket interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

func decryptPacket(c ConnCipher, p BytesPool, dist, src []byte) (n int, addr net.Addr, err error) {
	plain := getBytes(p)
	defer putBytes(p, plain)
	i, err := c.Decrypt(plain, src)
	if err != nil {
		return 0, nil, err
	}
	buf := bytes.NewBuffer(plain[:i])
	a, err := readAddress(buf)
	if err == nil {
		addr, err = toUDPAddr(a)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	return copy(dist, buf.Bytes()), addr, nil
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
		if a.IP == nil {
			// FQDN address, needs resolving.
			return net.ResolveUDPAddr("udp", a.Address())
		}
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
