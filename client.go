package shadowsocks

import (
	"context"
	"fmt"
	"github.com/wzshiming/shadowsocks/internal/socks"
	"net"
	"time"
)

// Dialer is a shadowsocks dialer.
type Dialer struct {
	// ProxyNetwork network between a proxy server and a client
	ProxyNetwork string
	// ProxyAddress proxy server address
	ProxyAddress string
	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
	// CipherName is the name of the cipher
	CipherName string
	// Password use password authentication
	Password string
	// Cipher encrypts the traffic
	Cipher Cipher
	// IsResolve resolve domain name on locally
	IsResolve bool
	// Resolver optionally specifies an alternate resolver to use
	Resolver *net.Resolver
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. The default is no timeout
	Timeout time.Duration
}

// NewDialer returns a new Dialer that dials through the provided
// proxy server's network and address.
func NewDialer(addr string) (*Dialer, error) {
	cfg, err := parseProxyURL(addr)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		ProxyNetwork: "tcp",
		ProxyAddress: cfg.Address,
		CipherName:   cfg.CipherName,
		Password:     cfg.Password,
		Cipher:       cfg.Cipher,
		Timeout:      time.Minute,
	}, nil
}

// DialContext connect to the provided address on the provided network.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	case "tcp", "tcp4", "tcp6":
		return d.connect(ctx, address)
	}
}

// Dial connect to the provided address on the provided network.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) connect(ctx context.Context, address string) (net.Conn, error) {
	if d.IsResolve {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if host != "" {
			ip := net.ParseIP(host)
			if ip == nil {
				ipaddr, err := d.resolver().LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
				host := ipaddr[0].String()
				address = net.JoinHostPort(host, port)
			}
		}
	}

	addr, err := socks.ParseAddr(address)
	if err != nil {
		return nil, err
	}

	conn, err := d.proxyDial(ctx, d.ProxyNetwork, d.ProxyAddress)
	if err != nil {
		return nil, err
	}

	if d.Timeout != 0 {
		deadline := time.Now().Add(d.Timeout)
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	stream, err := d.Cipher.ClientConn(conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return stream, nil
}

func (d *Dialer) resolver() *net.Resolver {
	if d.Resolver == nil {
		return net.DefaultResolver
	}
	return d.Resolver
}

func (d *Dialer) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := d.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}
