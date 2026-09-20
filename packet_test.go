package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	errBoom   = errors.New("boom")
	errCipher = errors.New("cipher unavailable")
	srcAddr   = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}
	destAddr  = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1002}
)

type plainCipher struct{}

func (plainCipher) StreamConn(conn net.Conn) net.Conn     { return conn }
func (plainCipher) Decrypt(dist, src []byte) (int, error) { return copy(dist, src), nil }
func (plainCipher) Encrypt(dist, src []byte) (int, error) { return copy(dist, src), nil }

type failingCipher struct {
	plainCipher
	err error
}

func (c failingCipher) Decrypt([]byte, []byte) (int, error) { return 0, c.err }

type countingPool struct{ gets, puts atomic.Int32 }

func (p *countingPool) Get() []byte { p.gets.Add(1); return make([]byte, 32*1024) }
func (p *countingPool) Put([]byte)  { p.puts.Add(1) }

type fakeRead struct {
	data []byte
	addr net.Addr
	err  error
}

type fakeWrite struct {
	data []byte
	addr net.Addr
}

type fakePacketConn struct {
	reads     chan fakeRead
	writes    chan fakeWrite
	done      chan struct{}
	once      sync.Once
	readCalls atomic.Int32
	closes    atomic.Int32
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		reads:  make(chan fakeRead, 8),
		writes: make(chan fakeWrite, 8),
		done:   make(chan struct{}),
	}
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readCalls.Add(1)
	select {
	case item := <-c.reads:
		if item.err != nil {
			return 0, nil, item.err
		}
		return copy(b, item.data), item.addr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case c.writes <- fakeWrite{data: append([]byte(nil), b...), addr: addr}:
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *fakePacketConn) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

func plainPacket(t *testing.T, addr net.Addr, payload string) []byte {
	t.Helper()
	buf := make([]byte, 64)
	n, err := encryptPacket(plainCipher{}, nil, buf, []byte(payload), addr)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	var value T
	select {
	case value = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
	return value
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func tableLen(p *PacketServer) int {
	p.connTableMut.Lock()
	defer p.connTableMut.Unlock()
	return len(p.connTable)
}

func TestPacketClientReadFromDiscardsInvalid(t *testing.T) {
	fake := newFakePacketConn()
	fake.reads <- fakeRead{data: []byte{0x00, 1, 2, 3}, addr: srcAddr}
	fake.reads <- fakeRead{data: []byte{ipv4Address, 1, 2}, addr: srcAddr}
	fake.reads <- fakeRead{data: plainPacket(t, destAddr, "hi"), addr: srcAddr}
	fake.reads <- fakeRead{err: errBoom}
	fake.reads <- fakeRead{err: errBoom}

	client := &packetClient{PacketConn: fake, Encryptor: plainCipher{}, Peer: srcAddr}
	buf := make([]byte, 64)
	n, addr, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" || addr.String() != destAddr.String() {
		t.Fatalf("got %q from %v", buf[:n], addr)
	}
	if _, _, err = client.ReadFrom(buf); err != errBoom {
		t.Fatalf("got %v, want errBoom", err)
	}
	if got := fake.readCalls.Load(); got != 4 {
		t.Fatalf("readCalls = %d, want 4", got)
	}
}

var cipherErrorCases = []struct {
	name      string
	decrypt   error
	want      error
	readCalls int32
}{
	{"operational", errCipher, errCipher, 1},
	{"malformed", fmt.Errorf("%w: bad tag", ErrInvalidPacket), errBoom, 2},
}

func TestPacketClientReadFromCipherError(t *testing.T) {
	for _, tt := range cipherErrorCases {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakePacketConn()
			fake.reads <- fakeRead{data: plainPacket(t, destAddr, "hi"), addr: srcAddr}
			fake.reads <- fakeRead{err: errBoom}
			pool := &countingPool{}
			client := &packetClient{PacketConn: fake, Encryptor: failingCipher{err: tt.decrypt}, BytesPool: pool, Peer: srcAddr}
			if _, _, err := client.ReadFrom(make([]byte, 64)); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if got := fake.readCalls.Load(); got != tt.readCalls {
				t.Fatalf("readCalls = %d, want %d", got, tt.readCalls)
			}
			if gets, puts := pool.gets.Load(), pool.puts.Load(); gets != puts {
				t.Fatalf("pool gets %d, puts %d", gets, puts)
			}
		})
	}
}

func TestPacketServerCipherError(t *testing.T) {
	for _, tt := range cipherErrorCases {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPacketServer()
			p.ConnCipher = failingCipher{err: tt.decrypt}
			lc := newFakePacketConn()
			lc.reads <- fakeRead{data: plainPacket(t, destAddr, "hi"), addr: srcAddr}
			lc.reads <- fakeRead{err: errBoom}
			if err := p.ServePacket(lc); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if got := lc.readCalls.Load(); got != tt.readCalls {
				t.Fatalf("readCalls = %d, want %d", got, tt.readCalls)
			}
		})
	}
}

func TestPacketServerDiscardsInvalidDatagram(t *testing.T) {
	forward := newFakePacketConn()
	p := NewPacketServer()
	p.ConnCipher = plainCipher{}
	p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) { return forward, nil }

	lc := newFakePacketConn()
	lc.reads <- fakeRead{data: []byte{0x00, 1, 2, 3}, addr: srcAddr}
	lc.reads <- fakeRead{data: plainPacket(t, destAddr, "hi"), addr: srcAddr}

	errc := make(chan error, 1)
	go func() { errc <- p.ServePacket(lc) }()

	select {
	case write := <-forward.writes:
		if string(write.data) != "hi" || write.addr.String() != destAddr.String() {
			t.Fatalf("forwarded %q to %v", write.data, write.addr)
		}
	case err := <-errc:
		t.Fatalf("ServePacket exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no forward write")
	}

	lc.reads <- fakeRead{err: errBoom}
	if err := recv(t, errc); err != errBoom {
		t.Fatalf("got %v, want errBoom", err)
	}
	if got := lc.readCalls.Load(); got != 3 {
		t.Fatalf("readCalls = %d, want 3", got)
	}
}

func TestPacketServerReturnsBufferOnReadError(t *testing.T) {
	pool := &countingPool{}
	p := NewPacketServer()
	p.ConnCipher = plainCipher{}
	p.BytesPool = pool
	lc := newFakePacketConn()
	lc.reads <- fakeRead{err: errBoom}
	if err := p.ServePacket(lc); err != errBoom {
		t.Fatalf("got %v, want errBoom", err)
	}
	if gets, puts := pool.gets.Load(), pool.puts.Load(); gets != puts {
		t.Fatalf("pool gets %d, puts %d", gets, puts)
	}
}

func TestPacketServerGC(t *testing.T) {
	fresh, stale := newFakePacketConn(), newFakePacketConn()
	p := NewPacketServer()
	p.connTable[sessionKey{src: "fresh"}] = &session{last: time.Now().Add(-time.Second), conn: fresh}
	p.connTable[sessionKey{src: "stale"}] = &session{last: time.Now().Add(-2 * time.Minute), conn: stale}
	p.gc()
	if _, ok := p.connTable[sessionKey{src: "fresh"}]; !ok || len(p.connTable) != 1 {
		t.Fatalf("table = %v", p.connTable)
	}
	if fresh.closes.Load() != 0 || stale.closes.Load() != 1 {
		t.Fatalf("closes fresh %d, stale %d", fresh.closes.Load(), stale.closes.Load())
	}
}

func TestPacketServerShutdownClosesSessions(t *testing.T) {
	forward := newFakePacketConn()
	pool := &countingPool{}
	p := NewPacketServer()
	p.ConnCipher = plainCipher{}
	p.BytesPool = pool
	p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) { return forward, nil }

	lc := newFakePacketConn()
	lc.reads <- fakeRead{data: plainPacket(t, destAddr, "hi"), addr: srcAddr}
	errc := make(chan error, 1)
	go func() { errc <- p.ServePacket(lc) }()
	recv(t, forward.writes)

	lc.reads <- fakeRead{err: errBoom}
	if err := recv(t, errc); err != errBoom {
		t.Fatalf("got %v, want errBoom", err)
	}
	if got := forward.closes.Load(); got != 1 {
		t.Fatalf("forward closes = %d, want 1", got)
	}
	if got := tableLen(p); got != 0 {
		t.Fatalf("table len = %d, want 0", got)
	}
	waitFor(t, "pool balanced", func() bool { return pool.gets.Load() == pool.puts.Load() })
	if got := forward.closes.Load(); got != 1 {
		t.Fatalf("forward closes = %d after reader exit, want 1", got)
	}
}

func TestPacketServerShutdownKeepsOtherServeSessions(t *testing.T) {
	otherSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 1003}
	for _, tt := range []struct {
		name string
		src  net.Addr
	}{{"distinct", otherSrc}, {"same", srcAddr}} {
		t.Run(tt.name, func(t *testing.T) {
			forwardA, forwardB := newFakePacketConn(), newFakePacketConn()
			forwards := make(chan net.PacketConn, 2)
			forwards <- forwardA
			forwards <- forwardB
			p := NewPacketServer()
			p.ConnCipher = plainCipher{}
			p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) { return <-forwards, nil }

			lcA, lcB := newFakePacketConn(), newFakePacketConn()
			errA, errB := make(chan error, 1), make(chan error, 1)
			lcA.reads <- fakeRead{data: plainPacket(t, destAddr, "a"), addr: srcAddr}
			go func() { errA <- p.ServePacket(lcA) }()
			recv(t, forwardA.writes)
			lcB.reads <- fakeRead{data: plainPacket(t, destAddr, "b"), addr: tt.src}
			go func() { errB <- p.ServePacket(lcB) }()
			recv(t, forwardB.writes)

			lcA.reads <- fakeRead{err: errBoom}
			if err := recv(t, errA); err != errBoom {
				t.Fatalf("got %v, want errBoom", err)
			}
			if forwardA.closes.Load() != 1 || forwardB.closes.Load() != 0 || tableLen(p) != 1 {
				t.Fatalf("closes A %d, B %d, table len %d", forwardA.closes.Load(), forwardB.closes.Load(), tableLen(p))
			}

			forwardB.reads <- fakeRead{data: []byte("reply"), addr: destAddr}
			if write := recv(t, lcB.writes); string(write.data) != string(plainPacket(t, destAddr, "reply")) || write.addr.String() != tt.src.String() {
				t.Fatalf("replied %q to %v", write.data, write.addr)
			}
			lcB.reads <- fakeRead{err: errBoom}
			recv(t, errB)
			if forwardB.closes.Load() != 1 || tableLen(p) != 0 {
				t.Fatalf("B closes %d, table len %d", forwardB.closes.Load(), tableLen(p))
			}
		})
	}
}

func TestPacketServerShutdownClosesPendingSession(t *testing.T) {
	forward := newFakePacketConn()
	entered, release := make(chan struct{}), make(chan struct{})
	p := NewPacketServer()
	p.ConnCipher = plainCipher{}
	p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) {
		close(entered)
		<-release
		return forward, nil
	}

	lc := newFakePacketConn()
	lc.reads <- fakeRead{data: plainPacket(t, destAddr, "hi"), addr: srcAddr}
	errc := make(chan error, 1)
	go func() { errc <- p.ServePacket(lc) }()
	recv(t, entered)

	lc.reads <- fakeRead{err: errBoom}
	if err := recv(t, errc); err != errBoom {
		t.Fatalf("got %v, want errBoom", err)
	}
	close(release)
	waitFor(t, "pending forward closed", func() bool { return forward.closes.Load() == 1 })
	if got := tableLen(p); got != 0 {
		t.Fatalf("table len = %d, want 0", got)
	}
	select {
	case write := <-forward.writes:
		t.Fatalf("unexpected write %q after shutdown", write.data)
	default:
	}
}

func TestPacketServerReaderExitClosesSession(t *testing.T) {
	forward := newFakePacketConn()
	p := NewPacketServer()
	p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) { return forward, nil }
	ps := &packetServer{PacketConn: newFakePacketConn(), Encryptor: plainCipher{}}
	if _, err := p.session(context.Background(), ps, srcAddr, destAddr); err != nil {
		t.Fatal(err)
	}
	forward.reads <- fakeRead{err: errBoom}
	waitFor(t, "forward closed", func() bool { return forward.closes.Load() == 1 })
	if got := tableLen(p); got != 0 {
		t.Fatalf("table len = %d, want 0", got)
	}
}

func TestPacketServerReaderExitKeepsReplacement(t *testing.T) {
	first, second := newFakePacketConn(), newFakePacketConn()
	forwards := make(chan net.PacketConn, 2)
	forwards <- first
	forwards <- second
	pool := &countingPool{}
	p := NewPacketServer()
	p.BytesPool = pool
	p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) { return <-forwards, nil }
	ps := &packetServer{PacketConn: newFakePacketConn(), Encryptor: plainCipher{}}
	ctx := context.Background()
	if _, err := p.session(ctx, ps, srcAddr, destAddr); err != nil {
		t.Fatal(err)
	}
	key := sessionKey{owner: ps, src: srcAddr.String(), dest: destAddr.String()}
	// Window between gc removing the entry and the first reader noticing.
	p.connTableMut.Lock()
	delete(p.connTable, key)
	p.connTableMut.Unlock()
	replacement, err := p.session(ctx, ps, srcAddr, destAddr)
	if err != nil {
		t.Fatal(err)
	}

	first.reads <- fakeRead{err: errBoom}
	waitFor(t, "first reader exit", func() bool { return pool.puts.Load() == 1 })
	p.connTableMut.Lock()
	defer p.connTableMut.Unlock()
	if p.connTable[key] != replacement {
		t.Fatalf("table[key] = %v, want replacement", p.connTable[key])
	}
	if got := second.closes.Load(); got != 0 {
		t.Fatalf("replacement closes = %d, want 0", got)
	}
}

func TestPacketServerSessionConcurrentSameKey(t *testing.T) {
	first, second := newFakePacketConn(), newFakePacketConn()
	forwards := make(chan net.PacketConn, 2)
	forwards <- first
	forwards <- second
	var entered sync.WaitGroup
	entered.Add(2)
	release := make(chan struct{})
	p := NewPacketServer()
	p.ProxyPacket = func(context.Context, string, string) (net.PacketConn, error) {
		entered.Done()
		<-release
		return <-forwards, nil
	}
	ps := &packetServer{PacketConn: newFakePacketConn(), Encryptor: plainCipher{}}

	results := make(chan *session, 2)
	for i := 0; i != 2; i++ {
		go func() {
			sess, err := p.session(context.Background(), ps, srcAddr, destAddr)
			if err != nil {
				t.Error(err)
			}
			results <- sess
		}()
	}
	entered.Wait()
	close(release)
	if recv(t, results) != recv(t, results) {
		t.Fatal("distinct sessions for one key")
	}
	if got := first.closes.Load() + second.closes.Load(); got != 1 {
		t.Fatalf("redundant forward closes = %d, want 1", got)
	}
	if got := tableLen(p); got != 1 {
		t.Fatalf("table len = %d, want 1", got)
	}
}
