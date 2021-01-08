package shadowsocks

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

// address is a SOCKS-specific address.
// Either Name or IP is used exclusively.
type address struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

func (a *address) Network() string { return "socks5" }

func (a *address) String() string {
	if a == nil {
		return "<nil>"
	}
	return a.Address()
}

// address returns a string suitable to dial; prefer returning IP-based
// address, fallback to Name
func (a address) Address() string {
	port := strconv.Itoa(a.Port)
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), port)
	}
	return net.JoinHostPort(a.Name, port)
}

func parseAddress(s string) (*address, error) {
	var addr address
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

func readAddress(r io.Reader) (*address, error) {
	address := &address{}

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

func writeAddress(w io.Writer, addr *address) error {
	if addr == nil {
		_, err := w.Write([]byte{ipv4Address, 0, 0, 0, 0, 0, 0})
		if err != nil {
			return err
		}
		return nil
	}
	if addr.IP != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			_, err := w.Write([]byte{ipv4Address})
			if err != nil {
				return err
			}
			_, err = w.Write(ip4)
			if err != nil {
				return err
			}
		} else if ip6 := addr.IP.To16(); ip6 != nil {
			_, err := w.Write([]byte{ipv6Address})
			if err != nil {
				return err
			}
			_, err = w.Write(ip6)
			if err != nil {
				return err
			}
		} else {
			_, err := w.Write([]byte{ipv4Address, 0, 0, 0, 0})
			if err != nil {
				return err
			}
		}
	} else if addr.Name != "" {
		if len(addr.Name) > 255 {
			return errStringTooLong
		}
		_, err := w.Write([]byte{fqdnAddress, byte(len(addr.Name))})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(addr.Name))
		if err != nil {
			return err
		}
	} else {
		_, err := w.Write([]byte{ipv4Address, 0, 0, 0, 0})
		if err != nil {
			return err
		}
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(addr.Port))
	_, err := w.Write(p[:])
	return err
}
