package shadowsocks

import (
	"context"
	"net"
	"net/url"
)

// SimpleServer is a simplified server, which can be configured as easily as client.
type SimpleServer struct {
	Server
	Listener net.Listener
	Network  string
	Address  string
}

// NewServer creates a new NewSimpleServer
func NewSimpleServer(addr string) (*SimpleServer, error) {
	cfg, err := parseProxyURL(addr)
	if err != nil {
		return nil, err
	}
	s := &SimpleServer{
		Network: "tcp",
		Address: cfg.Address,
	}
	s.Cipher = cfg.Cipher
	s.Password = cfg.Password
	s.ConnCipher = cfg.ConnCipher
	return s, nil
}

// Run the server
func (s *SimpleServer) Run(ctx context.Context) error {
	var listenConfig net.ListenConfig
	if s.Listener == nil {
		listener, err := listenConfig.Listen(ctx, s.Network, s.Address)
		if err != nil {
			return err
		}
		s.Listener = listener
	}
	s.Address = s.Listener.Addr().String()
	return s.Serve(s.Listener)
}

// Start the server
func (s *SimpleServer) Start(ctx context.Context) error {
	var listenConfig net.ListenConfig
	if s.Listener == nil {
		listener, err := listenConfig.Listen(ctx, s.Network, s.Address)
		if err != nil {
			return err
		}
		s.Listener = listener
	}
	s.Address = s.Listener.Addr().String()
	go s.Serve(s.Listener)
	return nil
}

// Close closes the listener
func (s *SimpleServer) Close() error {
	if s.Listener == nil {
		return nil
	}
	return s.Listener.Close()
}

// ProxyURL returns the URL of the proxy
func (s *SimpleServer) ProxyURL() string {
	u := url.URL{
		Scheme: "ss",
		User:   url.UserPassword(s.Cipher, s.Password),
		Host:   s.Address,
	}
	return u.String()
}
