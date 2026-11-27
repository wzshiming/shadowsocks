//go:build e2e

// Package e2e checks interoperability with shadowsocks-rust.
//
// It needs the ssserver and sslocal binaries of shadowsocks-rust in PATH:
//
//	go test -tags e2e ./e2e/
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/wzshiming/shadowsocks"
	_ "github.com/wzshiming/shadowsocks/init"
)

var methods = []struct {
	name string
	// keyLen is the size of the base64 key of a 2022 cipher, 0 for a plain password.
	keyLen int
}{
	{"2022-blake3-aes-128-gcm", 16},
	{"2022-blake3-aes-256-gcm", 32},
	{"2022-blake3-chacha20-poly1305", 32},
	{"aes-128-gcm", 0},
	{"aes-256-gcm", 0},
	{"chacha20-ietf-poly1305", 0},
}

func password(t *testing.T, keyLen int) string {
	if keyLen == 0 {
		return "e2e-password"
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func proxyURL(method, password, host string) string {
	u := url.URL{Scheme: "ss", User: url.UserPassword(method, password), Host: host}
	return u.String()
}

// freeAddr returns a loopback address whose port is free for TCP and UDP.
func freeAddr(t *testing.T) string {
	t.Helper()
	for i := 0; i != 20; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		p, err := net.ListenPacket("udp", addr)
		if err != nil {
			continue
		}
		p.Close()
		return addr
	}
	t.Fatal("no port free for both tcp and udp")
	return ""
}

// start runs a shadowsocks-rust binary until the test ends and waits for it
// to accept TCP connections on addr.
func start(t *testing.T, addr, name string, args ...string) {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s of shadowsocks-rust is required in PATH: %v", name, err)
	}
	var output bytes.Buffer
	cmd := exec.Command(path, args...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", name, output.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is not listening on %s: %v", name, addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startEcho runs a TCP and a UDP echo service.
func startEcho(t *testing.T) (tcp, udp net.Addr) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := p.ReadFrom(buf)
			if err != nil {
				return
			}
			p.WriteTo(buf[:n], addr)
		}
	}()
	return l.Addr(), p.LocalAddr()
}

// checkStream sends data of several sizes over an echoing conn. The large
// ones span many chunks in both directions.
func checkStream(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	for _, size := range []int{1, 1000, 300 * 1000} {
		data := make([]byte, size)
		rand.Read(data)
		errCh := make(chan error, 1)
		go func() {
			_, err := conn.Write(data)
			errCh <- err
		}()
		got := make([]byte, size)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read %d bytes: %v", size, err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("write %d bytes: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%d bytes came back different", size)
		}
	}
}

// checkPackets sends packets over an echoing conn. wrap and unwrap convert
// between payloads and the packets of conn.
func checkPackets(t *testing.T, conn net.PacketConn, to net.Addr, wrap, unwrap func([]byte) []byte) {
	t.Helper()
	buf := make([]byte, 64*1024)
	for i, size := range []int{1, 100, 1200, 1, 100, 1200} {
		data := make([]byte, size)
		rand.Read(data)
		data[0] = byte(i)
		// UDP is unreliable and the relay may still be starting: resend on timeout.
		for attempt := 0; ; attempt++ {
			if attempt == 10 {
				t.Fatalf("packet %d of %d bytes was not echoed", i, size)
			}
			if _, err := conn.WriteTo(wrap(data), to); err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			var got []byte
			for {
				n, _, err := conn.ReadFrom(buf)
				if err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						break
					}
					t.Fatal(err)
				}
				// Skip the late echo of an earlier packet.
				if got = unwrap(buf[:n]); bytes.Equal(got, data) {
					break
				}
				got = nil
			}
			if got != nil {
				break
			}
		}
	}
}

func same(b []byte) []byte { return b }

// TestClient checks our client against the shadowsocks-rust server.
func TestClient(t *testing.T) {
	tcpEcho, udpEcho := startEcho(t)
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			pass := password(t, m.keyLen)
			addr := freeAddr(t)
			start(t, addr, "ssserver", "-s", addr, "-m", m.name, "-k", pass, "-U")
			proxy := proxyURL(m.name, pass, addr)

			t.Run("tcp", func(t *testing.T) {
				dialer, err := shadowsocks.NewDialer(proxy)
				if err != nil {
					t.Fatal(err)
				}
				// More than one connection: each has its own salt.
				for i := 0; i != 2; i++ {
					conn, err := dialer.DialContext(context.Background(), "tcp", tcpEcho.String())
					if err != nil {
						t.Fatal(err)
					}
					checkStream(t, conn)
					conn.Close()
				}
			})
			t.Run("udp", func(t *testing.T) {
				client, err := shadowsocks.NewPacketClient(proxy)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := client.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				checkPackets(t, conn, udpEcho, same, same)
			})
		})
	}
}

// TestServer checks our server against the shadowsocks-rust client, which is
// driven through its SOCKS5 interface.
func TestServer(t *testing.T) {
	tcpEcho, udpEcho := startEcho(t)
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			pass := password(t, m.keyLen)
			addr := freeAddr(t)
			proxy := proxyURL(m.name, pass, addr)

			tcpServer, err := shadowsocks.NewSimpleServer(proxy)
			if err != nil {
				t.Fatal(err)
			}
			tcpServer.Logger = testLogger{t}
			if err := tcpServer.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer tcpServer.Close()
			udpServer, err := shadowsocks.NewSimplePacketServer(proxy)
			if err != nil {
				t.Fatal(err)
			}
			udpServer.Logger = testLogger{t}
			if err := udpServer.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer udpServer.Close()

			socks := freeAddr(t)
			start(t, socks, "sslocal", "-b", socks, "-s", addr, "-m", m.name, "-k", pass, "-U")

			t.Run("tcp", func(t *testing.T) {
				for i := 0; i != 2; i++ {
					conn, _ := socks5(t, socks, 1, tcpEcho)
					checkStream(t, conn)
					conn.Close()
				}
			})
			t.Run("udp", func(t *testing.T) {
				// The association lives as long as its TCP connection.
				control, relay := socks5(t, socks, 3, &net.UDPAddr{IP: net.IPv4zero})
				defer control.Close()
				conn, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				header := append([]byte{0, 0, 0}, socksAddr(t, udpEcho)...)
				wrap := func(b []byte) []byte { return append(append([]byte{}, header...), b...) }
				unwrap := func(b []byte) []byte {
					if !bytes.HasPrefix(b, header) {
						return nil
					}
					return b[len(header):]
				}
				checkPackets(t, conn, relay, wrap, unwrap)
			})
		})
	}
}

type testLogger struct{ t *testing.T }

func (l testLogger) Println(v ...interface{}) { l.t.Log(v...) }

// socksAddr encodes an IPv4 address as a SOCKS5 address.
func socksAddr(t *testing.T, addr net.Addr) []byte {
	t.Helper()
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	p, err := strconv.Atoi(port)
	if ip == nil || err != nil {
		t.Fatalf("%v is not an IPv4 address", addr)
	}
	return binary.BigEndian.AppendUint16(append([]byte{1}, ip...), uint16(p))
}

// socks5 sends a SOCKS5 command (1 connect, 3 udp associate) for target to
// the proxy and returns the connection and the address bound by the proxy.
func socks5(t *testing.T, proxy string, command byte, target net.Addr) (net.Conn, net.Addr) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := append([]byte{5, 1, 0, 5, command, 0}, socksAddr(t, target)...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	// Method selection (2 bytes), then the reply with an IPv4 address.
	reply := make([]byte, 2+10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("socks5 reply: %v", err)
	}
	if !bytes.Equal(reply[:6], []byte{5, 0, 5, 0, 0, 1}) {
		t.Fatalf("socks5 command %d failed: % x", command, reply)
	}
	conn.SetDeadline(time.Time{})
	bound := &net.UDPAddr{IP: net.IP(reply[6:10]), Port: int(binary.BigEndian.Uint16(reply[10:]))}
	if bound.IP.IsUnspecified() {
		bound.IP = net.IPv4(127, 0, 0, 1)
	}
	return conn, bound
}

func TestMain(m *testing.M) {
	for _, name := range []string{"ssserver", "sslocal"} {
		if _, err := exec.LookPath(name); err != nil {
			fmt.Fprintf(os.Stderr, "%s of shadowsocks-rust is required in PATH: %v\n", name, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}
