package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

type PacketClient struct {
	// ProxyNetwork network between a proxy server and a client
	ProxyNetwork string
	// ProxyAddress proxy server address
	ProxyAddress string
	// ProxyPacket specifies the optional dial function for
	// establishing the transport connection.
	ProxyPacket func(ctx context.Context, network, address string) (net.PacketConn, error)
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
	// BytesPool getting and returning temporary bytes
	BytesPool BytesPool
}

func NewPacketClient(addr string) (*PacketClient, error) {
	d := &PacketClient{
		ProxyNetwork: "udp",
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
		d.Cipher = u.User.Username()
		d.Password, _ = u.User.Password()
	}
	d.ProxyAddress = host
	cipher, err := NewCipher(d.Cipher, d.Password)
	if err != nil {
		return nil, err
	}
	d.ConnCipher = cipher
	return d, nil
}

func (l *PacketClient) proxyListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	proxyPacket := l.ProxyPacket
	if proxyPacket == nil {
		var listenConfig net.ListenConfig
		proxyPacket = listenConfig.ListenPacket
	}
	return proxyPacket(ctx, network, address)
}

func (l *PacketClient) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr(l.ProxyNetwork, l.ProxyAddress)
	if err != nil {
		return nil, err
	}
	conn, err := l.proxyListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn = &packetClient{
		PacketConn: conn,
		Encryptor:  l.ConnCipher,
		BytesPool:  l.BytesPool,
		Peer:       udpAddr,
	}
	return conn, nil
}

type packetClient struct {
	net.PacketConn
	Encryptor ConnCipher
	BytesPool BytesPool
	Peer      net.Addr
}

func (p *packetClient) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	n, a, err := p.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	n, addr, err = decryptPacket(p.Encryptor, p.BytesPool, b, buf[:n])
	if err != nil {
		return 0, nil, fmt.Errorf("from %v: %v", a, err)
	}
	addr, err = toUDPAddr(addr)
	if err != nil {
		return 0, nil, err
	}
	return n, addr, nil
}

func (p *packetClient) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	n, err = encryptPacket(p.Encryptor, p.BytesPool, buf, b, addr)
	if err != nil {
		return 0, err
	}
	_, err = p.PacketConn.WriteTo(buf[:n], p.Peer)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
