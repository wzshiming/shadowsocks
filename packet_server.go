package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	// Logger error log
	Logger Logger
	// BytesPool getting and returning temporary bytes
	BytesPool BytesPool

	connTableMut sync.Mutex
	connTable    map[sessionKey]*session
}

// sessionKey scopes a relay session to the ServePacket call that admitted it.
type sessionKey struct {
	owner     *packetServer
	src, dest string
}

type session struct {
	last time.Time
	conn net.PacketConn
	// reply encrypts the packets sent back to the client, it follows the
	// latest packet of the client. Guarded by connTableMut.
	reply PacketEncrypter
}

func NewPacketServer() *PacketServer {
	return &PacketServer{
		Context:      context.Background(),
		ProxyNetwork: "udp",
		connTable:    map[sessionKey]*session{},
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
		Encryptor:  p.Cipher,
		Logger:     p.Logger,
	}
	ctx, cancel := context.WithCancel(p.context())
	defer func() {
		cancel()
		p.evict(func(key sessionKey, _ *session) bool { return key.owner == ps })
	}()
	go p.gcTask(ctx)
	for {
		buf := getBytes(p.BytesPool)
		i, src, dest, reply, err := ps.readFrom(buf[:])
		if err != nil {
			putBytes(p.BytesPool, buf)
			return err
		}
		go func() {
			defer putBytes(p.BytesPool, buf)
			p.forward(ctx, ps, src, dest, reply, buf[:i])
		}()
	}
}

func (p *PacketServer) gcTask(ctx context.Context) {
	tick := time.NewTicker(p.timeout())
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			p.gc()
		case <-ctx.Done():
			return
		}
	}
}

func (p *PacketServer) timeout() time.Duration {
	if p.Timeout == 0 {
		return time.Minute
	}
	return p.Timeout
}

func (p *PacketServer) gc() {
	deadline := time.Now().Add(-p.timeout())
	p.evict(func(_ sessionKey, sess *session) bool { return deadline.After(sess.last) })
}

// evict removes matching sessions from the table and closes them outside the lock.
func (p *PacketServer) evict(match func(sessionKey, *session) bool) {
	var evicted []*session
	p.connTableMut.Lock()
	for key, sess := range p.connTable {
		if match(key, sess) {
			delete(p.connTable, key)
			evicted = append(evicted, sess)
		}
	}
	p.connTableMut.Unlock()
	for _, sess := range evicted {
		sess.conn.Close()
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

func (p *PacketServer) forward(ctx context.Context, conn *packetServer, src, dest net.Addr, reply PacketEncrypter, buf []byte) {
	sess, err := p.session(ctx, conn, src, dest, reply)
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

func (p *PacketServer) session(ctx context.Context, conn *packetServer, src, dest net.Addr, reply PacketEncrypter) (*session, error) {
	key := sessionKey{owner: conn, src: src.String(), dest: dest.String()}

	p.connTableMut.Lock()
	sess, ok := p.connTable[key]
	if ok {
		sess.last = time.Now()
		sess.reply = reply
		p.connTableMut.Unlock()
		return sess, nil
	}
	p.connTableMut.Unlock()

	forward, err := p.proxyListenPacket(ctx, p.ProxyNetwork, ":0")
	if err != nil {
		return nil, err
	}

	sess = &session{
		last:  time.Now(),
		conn:  forward,
		reply: reply,
	}
	// Re-check to avoid leaking forward when another goroutine won the race.
	p.connTableMut.Lock()
	if err := ctx.Err(); err != nil {
		p.connTableMut.Unlock()
		forward.Close()
		return nil, err
	}
	if exist, ok := p.connTable[key]; ok {
		exist.last = time.Now()
		exist.reply = reply
		p.connTableMut.Unlock()
		forward.Close()
		return exist, nil
	}
	p.connTable[key] = sess
	p.connTableMut.Unlock()

	go func() {
		buf := getBytes(p.BytesPool)
		defer putBytes(p.BytesPool, buf)
		defer func() {
			// Whoever removes the table entry closes the forward.
			p.connTableMut.Lock()
			if p.connTable[key] != sess {
				p.connTableMut.Unlock()
				return
			}
			delete(p.connTable, key)
			p.connTableMut.Unlock()
			forward.Close()
		}()
		reply := dest.String()
		for {
			n, addr, err := forward.ReadFrom(buf[:])
			if err != nil {
				if p.Logger != nil && !errors.Is(err, net.ErrClosed) {
					p.Logger.Println(err)
				}
				return
			}
			if addr.String() != reply {
				continue
			}
			p.connTableMut.Lock()
			enc := sess.reply
			p.connTableMut.Unlock()
			_, err = conn.writeTo(enc, buf[:n], dest, src)
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
	Encryptor Cipher
	BytesPool BytesPool
	Logger    Logger
}

// readFrom reads the next valid packet. reply encrypts the packets sent back to its sender.
// requestDecrypter decrypts the requests a server receives and keeps the
// encrypter for the replies to the last one.
type requestDecrypter struct {
	cipher Cipher
	reply  PacketEncrypter
}

func (d *requestDecrypter) Decrypt(dist, src []byte) (n int, err error) {
	n, d.reply, err = d.cipher.ServerPacket(dist, src)
	return n, err
}

func (p *packetServer) readFrom(b []byte) (n int, ori, addr net.Addr, reply PacketEncrypter, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	request := requestDecrypter{cipher: p.Encryptor}
	for {
		n, a, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, nil, nil, err
		}
		n, addr, err = decryptPacket(&request, p.BytesPool, b, buf[:n])
		if err == nil {
			return n, a, addr, request.reply, nil
		}
		if !errors.Is(err, ErrInvalidPacket) {
			return 0, nil, nil, nil, err
		}
		if p.Logger != nil {
			p.Logger.Println(fmt.Errorf("from %v: %v", a, err))
		}
	}
}

func (p *packetServer) writeTo(reply PacketEncrypter, b []byte, ori, addr net.Addr) (n int, err error) {
	buf := getBytes(p.BytesPool)
	defer putBytes(p.BytesPool, buf)
	n, err = encryptPacket(reply, p.BytesPool, buf, b, ori)
	if err != nil {
		return 0, err
	}
	_, err = p.PacketConn.WriteTo(buf[:n], addr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
