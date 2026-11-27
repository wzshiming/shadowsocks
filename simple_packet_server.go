package shadowsocks

import (
	"context"
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
	cfg, err := parseProxyURL(addr)
	if err != nil {
		return nil, err
	}
	s := &SimplePacketServer{
		PacketServer: *NewPacketServer(),
		Network:      "udp",
		Address:      cfg.Address,
	}
	s.CipherName = cfg.CipherName
	s.Password = cfg.Password
	s.Cipher = cfg.Cipher
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
		User:   url.UserPassword(s.CipherName, s.Password),
		Host:   s.Address,
	}
	return u.String()
}
