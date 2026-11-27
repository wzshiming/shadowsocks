package shadowsocks

import (
	"bytes"
	"context"
	"fmt"
	"github.com/wzshiming/shadowsocks/internal/socks"
	"net"
)

type ListenPacket interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

func decryptPacket(c PacketDecrypter, p BytesPool, dist, src []byte) (n int, addr net.Addr, err error) {
	plain := getBytes(p)
	defer putBytes(p, plain)
	i, err := c.Decrypt(plain, src)
	if err != nil {
		return 0, nil, err
	}
	buf := bytes.NewBuffer(plain[:i])
	a, err := socks.ReadAddr(buf)
	if err == nil {
		addr, err = toUDPAddr(a)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	return copy(dist, buf.Bytes()), addr, nil
}

func encryptPacket(c PacketEncrypter, p BytesPool, dist, src []byte, addr net.Addr) (n int, err error) {
	a, err := socks.ParseAddr(addr.String())
	if err != nil {
		return 0, err
	}
	buf := getBytes(p)
	defer putBytes(p, buf)
	plain, err := socks.AppendAddr(buf[:0], a)
	if err != nil {
		return 0, err
	}
	plain = append(plain, src...)
	i, err := c.Encrypt(dist, plain)
	if err != nil {
		return 0, err
	}
	return i, nil
}

func toUDPAddr(addr net.Addr) (net.Addr, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return addr, nil
	case *Addr:
		if a.IP == nil {
			// FQDN address, needs resolving.
			return net.ResolveUDPAddr("udp", a.Address())
		}
		return &net.UDPAddr{IP: a.IP, Port: a.Port}, nil
	default:
		return net.ResolveUDPAddr("udp", addr.String())
	}
}
