package shadowsocks_test

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wzshiming/shadowsocks"
	"github.com/wzshiming/shadowsocks/aead"
	_ "github.com/wzshiming/shadowsocks/init"
	"github.com/wzshiming/shadowsocks/stream"
)

var list = []string{
	"dummy",
	"aes-128-cfb",
	"aes-128-ctr",
	"aes-128-gcm",
	"aes-192-cfb",
	"aes-192-ctr",
	"aes-192-gcm",
	"aes-256-cfb",
	"aes-256-ctr",
	"aes-256-gcm",
	"bf-cfb",
	"cast5-cfb",
	"chacha20",
	"chacha20-ietf",
	"xchacha20",
	"chacha20-ietf-poly1305",
	"xchacha20-poly1305",
	"des-cfb",
	"rc4-md5",
	"rc4-md5-6",
	"salsa20",

	"dummy:123",
	"aes-128-cfb:123",
	"aes-128-ctr:123",
	"aes-128-gcm:123",
	"aes-192-cfb:123",
	"aes-192-ctr:123",
	"aes-192-gcm:123",
	"aes-256-cfb:123",
	"aes-256-ctr:123",
	"aes-256-gcm:123",
	"bf-cfb:123",
	"cast5-cfb:123",
	"chacha20:123",
	"chacha20-ietf:123",
	"xchacha20:123",
	"chacha20-ietf-poly1305:123",
	"xchacha20-poly1305:123",
	"des-cfb:123",
	"rc4-md5:123",
	"rc4-md5-6:123",
	"salsa20:123",

	"YWVzLTEyOC1jZmI6MTIzNDU2Cg==",
}

func TestAll(t *testing.T) {
	svc := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}))

	for _, c := range list {
		t.Run(c, func(t *testing.T) {
			s, err := shadowsocks.NewSimpleServer("ss://" + c + "@:0")
			if err != nil {
				t.Fatal(err)
			}

			s.Start(context.Background())
			defer s.Close()

			d, err := shadowsocks.NewDialer(s.ProxyURL())
			if err != nil {
				t.Fatal(err)
			}
			transport := svc.Client().Transport.(*http.Transport).Clone()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				t.Log(c)
				return d.DialContext(ctx, network, addr)
			}
			c := http.Client{
				Transport: transport,
			}
			resp, err := c.Get(svc.URL)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fail()
			}
			resp.Body.Close()
			resp, err = c.Get(svc.URL)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fail()
			}
			resp.Body.Close()
		})
	}
}

func TestEncryptor(t *testing.T) {
	var tmp1 [255]byte
	var tmp2 [255]byte

	for _, c := range shadowsocks.CipherList() {
		t.Run(c, func(t *testing.T) {

			cipher, err := shadowsocks.NewCipher(c, "pwd")
			if err != nil {
				t.Fatal(err)
			}

			n1, err := cipher.Encrypt(tmp1[:], []byte(c))
			if err != nil {
				t.Fatal(err)
			}

			n2, err := cipher.Decrypt(tmp2[:], tmp1[:n1])
			if err != nil {
				t.Fatal(err)
			}
			if string(tmp2[:n2]) != c {
				t.Errorf("%q %q %q", c, tmp1[:n1], tmp2[:n2])
			}
		})
	}
}

func TestPacket(t *testing.T) {
	// echo server
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		var buf [1024 * 32]byte
		for {
			i, addr, err := p.ReadFrom(buf[:])
			if err != nil {
				t.Fatal(err)
			}
			tmp := append([]byte("echo "), buf[:i]...)
			_, err = p.WriteTo(tmp, addr)
			if err != nil {
				t.Fatal(err)
			}
		}
	}()

	remote, err := shadowsocks.NewSimplePacketServer("ss://YWVzLTEyOC1jZmI6MTIzNDU2Cg==@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	err = remote.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Log(remote.ProxyURL())
	local, err := shadowsocks.NewPacketClient(remote.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := local.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i != 10; i++ {
		tmp := fmt.Sprintf("hello %d", i)
		_, err = client.WriteTo([]byte(tmp), p.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		var buf [1024 * 32]byte
		i, addr, err := client.ReadFrom(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		if "echo "+tmp != string(buf[:i]) {
			t.Error("resp", i, string(buf[:i]), addr)
		}
	}
}

// startPacketEcho runs an echo peer behind a packet server and returns a client through it.
func startPacketEcho(t *testing.T, method string) (echo net.PacketConn, remote *shadowsocks.SimplePacketServer, client net.PacketConn) {
	t.Helper()
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		var buf [1024]byte
		for {
			n, addr, err := echo.ReadFrom(buf[:])
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo "), buf[:n]...), addr)
		}
	}()

	remote, err = shadowsocks.NewSimplePacketServer("ss://" + method + ":123@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { remote.Close() })

	local, err := shadowsocks.NewPacketClient(remote.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	client, err = local.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return echo, remote, client
}

func TestPacketDiscardInvalid(t *testing.T) {
	echo, remote, client := startPacketEcho(t, "aes-128-gcm")

	junk := [][]byte{nil, {1, 2, 3}, make([]byte, 64)}
	targets := []struct {
		name string
		addr net.Addr
	}{
		{"client", client.LocalAddr()},
		{"server", remote.PacketConn.LocalAddr()},
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			for _, datagram := range junk {
				if _, err := echo.WriteTo(datagram, target.addr); err != nil {
					t.Fatal(err)
				}
			}
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			for i := 0; i != 2; i++ {
				msg := fmt.Sprintf("hello %d", i)
				if _, err := client.WriteTo([]byte(msg), echo.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				var buf [1024]byte
				n, _, err := client.ReadFrom(buf[:])
				if err != nil {
					t.Fatal(err)
				}
				if got := string(buf[:n]); got != "echo "+msg {
					t.Fatalf("got %q, want %q", got, "echo "+msg)
				}
			}
		})
	}
}

func TestPacketReadFromSmallBuffer(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-128-cfb"} {
		t.Run(method, func(t *testing.T) {
			echo, _, client := startPacketEcho(t, method)
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			// A truncated read consumes its whole datagram; the next read must see the next one.
			for i, size := range []int{0, len("echo hello 1"), 1, 64} {
				msg := fmt.Sprintf("hello %d", i)
				if _, err := client.WriteTo([]byte(msg), echo.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, size)
				n, addr, err := client.ReadFrom(buf)
				if err != nil {
					t.Fatalf("buffer %d: %v", size, err)
				}
				want := "echo " + msg
				if size < len(want) {
					want = want[:size]
				}
				if got := string(buf[:n]); got != want || addr.String() != echo.LocalAddr().String() {
					t.Fatalf("buffer %d: got %q from %v, want %q", size, got, addr, want)
				}
			}
		})
	}
}

func TestDecryptInvalidPacket(t *testing.T) {
	errCipher := errors.New("cipher unavailable")
	gcm, err := shadowsocks.NewCipher("aes-128-gcm", "123")
	if err != nil {
		t.Fatal(err)
	}
	cfb, err := shadowsocks.NewCipher("aes-128-cfb", "123")
	if err != nil {
		t.Fatal(err)
	}
	var wire [64]byte
	sealed, err := gcm.Encrypt(wire[:], []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	brokenAEAD := &aead.Cipher{Key: make([]byte, 16), NewAEAD: func([]byte) (cipher.AEAD, error) { return nil, errCipher }}
	brokenStream := &stream.Cipher{Key: make([]byte, 16), IvLen: 16, NewDecrypt: func([]byte, []byte) (cipher.Stream, error) { return nil, errCipher }}

	tests := []struct {
		name   string
		cipher shadowsocks.ConnCipher
		dest   []byte
		src    []byte
		want   error
	}{
		{"aead truncated salt", gcm, make([]byte, 64), wire[:3], shadowsocks.ErrInvalidPacket},
		{"aead truncated tag", gcm, make([]byte, 64), wire[:20], shadowsocks.ErrInvalidPacket},
		{"aead bad auth", gcm, make([]byte, 64), make([]byte, 40), shadowsocks.ErrInvalidPacket},
		{"aead short dest", gcm, make([]byte, 2), wire[:sealed], io.ErrShortBuffer},
		{"aead init failure", brokenAEAD, make([]byte, 64), wire[:sealed], errCipher},
		{"stream truncated", cfb, make([]byte, 64), make([]byte, 16), shadowsocks.ErrInvalidPacket},
		{"stream init failure", brokenStream, make([]byte, 64), make([]byte, 20), errCipher},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cipher.Decrypt(tt.dest, tt.src)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if tt.want != shadowsocks.ErrInvalidPacket && errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("%v wrongly marked as invalid packet", err)
			}
		})
	}
}
