package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"net/url"
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
	// Cipher use cipher protocol
	Cipher string
	// Password use password authentication
	Password string
	// ConnCipher is connect the cipher codec
	ConnCipher ConnCipher
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
	d := &Dialer{
		ProxyNetwork: "tcp",
		Timeout:      time.Minute,
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "ss", "shadowsocks":
	default:
		return nil, fmt.Errorf("unsupported protocol '%s'", u.Scheme)
	}
	host := u.Host
	port := u.Port()
	if port == "" {
		port = "8379"
		hostname := u.Hostname()
		host = net.JoinHostPort(hostname, port)
	}
	if u.User != nil {
		d.Cipher, d.Password, err = GetCipherAndPasswordFromUserinfo(u.User)
		if err != nil {
			return nil, err
		}
	}
	d.ProxyAddress = host
	cipher, err := NewCipher(d.Cipher, d.Password)
	if err != nil {
		return nil, err
	}
	d.ConnCipher = cipher
	return d, nil
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

	addr, err := parseAddress(address)
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

	conn = d.ConnCipher.StreamConn(conn)

	err = writeAddress(conn, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
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
