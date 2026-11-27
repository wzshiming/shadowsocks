// Package socks encodes the addresses of the shadowsocks protocols, which
// use the format of SOCKS5.
package socks

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

var (
	errStringTooLong        = errors.New("string too long")
	errUnrecognizedAddrType = errors.New("unrecognized address type")
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	ipv4Address = 0x01
	fqdnAddress = 0x03
	ipv6Address = 0x04
)

// Addr is the target of a connection or a packet.
// Either Name or IP is used exclusively.
type Addr struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

func (a *Addr) Network() string { return "shadowsocks" }

func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	return a.Address()
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to Name
func (a Addr) Address() string {
	port := strconv.Itoa(a.Port)
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), port)
	}
	return net.JoinHostPort(a.Name, port)
}

// ParseAddr parses a "host:port" address.
func ParseAddr(s string) (*Addr, error) {
	var addr Addr
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr.IP = ip
	} else {
		if len(host) > 255 {
			return nil, errUnrecognizedAddrType
		}
		addr.Name = host
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}

	addr.Port = int(portNum)
	return &addr, nil
}

// ReadAddr reads an address in the SOCKS format.
func ReadAddr(r io.Reader) (*Addr, error) {
	address := &Addr{}

	var addrType [1]byte
	if _, err := r.Read(addrType[:]); err != nil {
		return nil, err
	}

	switch addrType[0] {
	case ipv4Address:
		addr := make(net.IP, net.IPv4len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		address.IP = addr
	case ipv6Address:
		addr := make(net.IP, net.IPv6len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		address.IP = addr
	case fqdnAddress:
		if _, err := r.Read(addrType[:]); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadFull(r, fqdn); err != nil {
			return nil, err
		}
		address.Name = string(fqdn)
	default:
		return nil, errUnrecognizedAddrType
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	address.Port = int(binary.BigEndian.Uint16(port[:]))
	return address, nil
}

// AppendAddr appends addr to b in the SOCKS format.
func AppendAddr(b []byte, addr *Addr) ([]byte, error) {
	port := 0
	switch {
	case addr == nil:
		b = append(b, ipv4Address, 0, 0, 0, 0)
	case addr.IP != nil:
		port = addr.Port
		if ip4 := addr.IP.To4(); ip4 != nil {
			b = append(append(b, ipv4Address), ip4...)
		} else if ip6 := addr.IP.To16(); ip6 != nil {
			b = append(append(b, ipv6Address), ip6...)
		} else {
			b = append(b, ipv4Address, 0, 0, 0, 0)
		}
	case addr.Name != "":
		port = addr.Port
		if len(addr.Name) > 255 {
			return nil, errStringTooLong
		}
		b = append(append(b, fqdnAddress, byte(len(addr.Name))), addr.Name...)
	default:
		port = addr.Port
		b = append(b, ipv4Address, 0, 0, 0, 0)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}
