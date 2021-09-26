package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type PacketServer struct {
	// ProxyNetwork network between a proxy server and a client
	ProxyNetwork string
	// ProxyAddress proxy server address
	ProxyAddress string
	// Context is default context
	Context context.Context
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
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. The default is no timeout
	Timeout time.Duration
	// Logger error log
	Logger Logger
	// BytesPool getting and returning temporary bytes
	BytesPool BytesPool

	connTableMut sync.Mutex
	connTable    map[string]*session
}

type session struct {
	last time.Time
	conn net.PacketConn
}

func NewPacketServer() *PacketServer {
	return &PacketServer{
		Context:      context.Background(),
		ProxyNetwork: "udp",
		connTable:    map[string]*session{},
	}
}

// ListenAndServe is used to create a listener and serve on it
func (p *PacketServer) ListenAndServe(network, addr string) error {
	var lc net.ListenConfig
	l, err := lc.ListenPacket(p.context(), network, addr)
	if err != nil {
		return err
	}
	return p.ServePacket(l)
}

func (p *PacketServer) ServePacket(conn net.PacketConn) error {
	ps := &packetServer{
		PacketConn: conn,
		BytesPool:  p.BytesPool,
		Encryptor:  p.ConnCipher,
	}
	ctx, cancel := context.WithCancel(p.context())
	defer cancel()
	go p.gcTask(ctx)
	for {
		buf := getBytes(p.BytesPool)
		i, src, dest, err := ps.readFrom(buf[:])
		if err != nil {
			return err
		}
		go func() {
			defer putBytes(p.BytesPool, buf)
			p.forward(ps, src, dest, buf[:i])
		}()
	}
}

func (p *PacketServer) gcTask(ctx context.Context) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	tick := time.NewTicker(timeout)
	for {
		select {
		case <-tick.C:
			p.gc()
		case <-ctx.Done():
			return
		}
	}
}

func (p *PacketServer) gc() {
	p.connTableMut.Lock()
	defer p.connTableMut.Unlock()
	deadline := time.Now().Add(-p.Timeout)
	for k, sess := range p.connTable {
		if deadline.After(sess.last) {
			sess.conn.SetDeadline(deadline)
			delete(p.connTable, k)
		}
	}
}

func (p *PacketServer) proxyListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	proxyPacket := p.ProxyPacket
	if proxyPacket == nil {
		var listenConfig net.ListenConfig
		proxyPacket = listenConfig.ListenPacket
	}
	return proxyPacket(ctx, network, address)
}

func (p *PacketServer) forward(conn *packetServer, src, dest net.Addr, buf []byte) {
	sess, err := p.session(conn, src, dest)
	if err != nil {
		if p.Logger != nil {
			p.Logger.Println(err)
		}
		return
	}
	_, err = sess.conn.WriteTo(buf, dest)
	if err != nil {
		if p.Logger != nil {
			p.Logger.Println(err)
		}
	}

}

func (p *PacketServer) session(conn *packetServer, src, dest net.Addr) (*session, error) {
	key := strings.Join([]string{src.String(), dest.String()}, "|")

	p.connTableMut.Lock()
	sess, ok := p.connTable[key]
	if ok {
		sess.last = time.Now()
		p.connTableMut.Unlock()
		return sess, nil
	}
	p.connTableMut.Unlock()

	forward, err := p.proxyListenPacket(p.context(), p.ProxyNetwork, ":0")
	if err != nil {
		return nil, err
	}

	sess = &session{
		last: time.Now(),
		conn: forward,
	}
	p.connTableMut.Lock()
	p.connTable[key] = sess
	p.connTableMut.Unlock()

	go func() {
		key := dest.String()
		buf := getBytes(p.BytesPool)
		defer putBytes(p.BytesPool, buf)
		for {
			n, addr, err := forward.ReadFrom(buf[:])
			if err != nil {
				if p.Logger != nil {
					p.Logger.Println(err)
				}
				return
			}
			if addr.String() != key {
				continue
			}
			_, err = conn.writeTo(buf[:n], dest, src)
			if err != nil {
				if p.Logger != nil {
					p.Logger.Println(err)
				}
				return
			}
		}
	}()
	return sess, nil
}

func (p *PacketServer) context() context.Context {
	if p.Context == nil {
		return context.Background()
	}
	return p.Context
}

type packetServer struct {
	net.PacketConn
	Encryptor ConnCipher
	BytesPool BytesPool
}

func (p *packetServer) readFrom(b []byte) (n int, ori, addr net.Addr, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	n, a, err := p.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, nil, err
	}
	n, addr, err = decryptPacket(p.Encryptor, p.BytesPool, b, buf[:n])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("from %v: %v", a, err)
	}
	addr, err = toUDPAddr(addr)
	if err != nil {
		return 0, nil, nil, err
	}
	return n, a, addr, nil
}

func (p *packetServer) writeTo(b []byte, ori, addr net.Addr) (n int, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	n, err = encryptPacket(p.Encryptor, p.BytesPool, buf, b, ori)
	if err != nil {
		return 0, err
	}
	_, err = p.PacketConn.WriteTo(buf[:n], addr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
