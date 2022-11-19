package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// SimplePacketServer is a simplified server, which can be configured as easily as client.
type SimplePacketServer struct {
	PacketServer
	PacketConn net.PacketConn
	Network    string
	Address    string
}

// NewSimplePacketServer creates a new NewSimplePacketServer
func NewSimplePacketServer(addr string) (*SimplePacketServer, error) {
	s := &SimplePacketServer{
		PacketServer: *NewPacketServer(),
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
		s.Cipher, s.Password, err = GetCipherAndPasswordFromUserinfo(u.User)
		if err != nil {
			return nil, err
		}
	}

	cipher, err := NewCipher(s.Cipher, s.Password)
	if err != nil {
		return nil, err
	}
	s.ConnCipher = cipher

	s.Address = host
	s.Network = "udp"
	return s, nil
}

// Run the PacketServer
func (s *SimplePacketServer) Run(ctx context.Context) error {
	var listenConfig net.ListenConfig
	if s.PacketConn == nil {
		packetConn, err := listenConfig.ListenPacket(ctx, s.Network, s.Address)
		if err != nil {
			return err
		}
		s.PacketConn = packetConn
	}
	s.Address = s.PacketConn.LocalAddr().String()
	return s.ServePacket(s.PacketConn)
}

// Start the PacketServer
func (s *SimplePacketServer) Start(ctx context.Context) error {
	var listenConfig net.ListenConfig
	if s.PacketConn == nil {
		packetConn, err := listenConfig.ListenPacket(ctx, s.Network, s.Address)
		if err != nil {
			return err
		}
		s.PacketConn = packetConn
	}
	s.Address = s.PacketConn.LocalAddr().String()
	go s.ServePacket(s.PacketConn)
	return nil
}

// Close closes the listener
func (s *SimplePacketServer) Close() error {
	if s.PacketConn == nil {
		return nil
	}
	return s.PacketConn.Close()
}

// ProxyURL returns the URL of the proxy
func (s *SimplePacketServer) ProxyURL() string {
	u := url.URL{
		Scheme: "ss",
		User:   url.UserPassword(s.Cipher, s.Password),
		Host:   s.Address,
	}
	return u.String()
}
