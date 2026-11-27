package shadowsocks

import (
	"context"
	"errors"
	"net"
)

type PacketClient struct {
	// ProxyNetwork network between a proxy server and a client
	ProxyNetwork string
	// ProxyAddress proxy server address
	ProxyAddress string
	// ProxyPacket specifies the optional dial function for
	// establishing the transport connection.
	ProxyPacket func(ctx context.Context, network, address string) (net.PacketConn, error)
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
	// BytesPool getting and returning temporary bytes
	BytesPool BytesPool
}

func NewPacketClient(addr string) (*PacketClient, error) {
	cfg, err := parseProxyURL(addr)
	if err != nil {
		return nil, err
	}
	return &PacketClient{
		ProxyNetwork: "udp",
		ProxyAddress: cfg.Address,
		CipherName:   cfg.CipherName,
		Password:     cfg.Password,
		Cipher:       cfg.Cipher,
	}, nil
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
	encryptor, err := l.Cipher.ClientPacket()
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = &packetClient{
		PacketConn: conn,
		Encryptor:  encryptor,
		BytesPool:  l.BytesPool,
		Peer:       udpAddr,
	}
	return conn, nil
}

type packetClient struct {
	net.PacketConn
	Encryptor PacketSession
	BytesPool BytesPool
	Peer      net.Addr
}

func (p *packetClient) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	for {
		n, _, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		n, addr, err = decryptPacket(p.Encryptor, p.BytesPool, b, buf[:n])
		if err == nil {
			return n, addr, nil
		}
		if !errors.Is(err, ErrInvalidPacket) {
			return 0, nil, err
		}
	}
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
