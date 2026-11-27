package aead2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/shadowsocks"
	"golang.org/x/crypto/chacha20poly1305"
)

var methods = []struct {
	name   string
	keyLen int
	chacha bool
}{
	{"2022-blake3-aes-128-gcm", 16, false},
	{"2022-blake3-aes-256-gcm", 32, false},
	{"2022-blake3-chacha20-poly1305", 32, true},
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var target = &shadowsocks.Addr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 80}

// newTestCipher builds a cipher the way the sub-packages register it, which
// can't be imported from here.
func newTestCipher(t *testing.T, keyLen int, chacha bool) *Cipher {
	t.Helper()
	key := bytes.Repeat([]byte{7}, keyLen)
	if chacha {
		packetAEAD, err := chacha20poly1305.NewX(key)
		if err != nil {
			t.Fatal(err)
		}
		return newCipher(key, chacha20poly1305.New, nil, packetAEAD)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return newCipher(key, newGCM, block, nil)
}

func eachMethod(t *testing.T, f func(t *testing.T, c *Cipher)) {
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) { f(t, newTestCipher(t, m.keyLen, m.chacha)) })
	}
}

func TestKey(t *testing.T) {
	encode := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	tests := []struct {
		keyLen int
		key    string
		ok     bool
	}{
		{16, encode(16), true},
		{16, strings.TrimRight(encode(16), "="), true},
		{16, encode(32), false},
		{32, encode(16), false},
		{32, encode(32), true},
		{32, "password", false},
		{16, encode(16) + ":" + encode(16), false},
	}
	for _, tt := range tests {
		key, err := decodeKey(tt.key, tt.keyLen)
		if (err == nil) != tt.ok || (tt.ok && len(key) != tt.keyLen) {
			t.Errorf("%d byte key %q: got %d bytes, err = %v, want ok = %v", tt.keyLen, tt.key, len(key), err, tt.ok)
		}
	}
}

func TestRegister(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	RegisterCipher("2022-test-block", 16, newGCM, aes.NewCipher)
	RegisterPacketAEADCipher("2022-test-packet-aead", 16, newGCM, newGCM)
	RegisterCipher("2022-test-bad-block", 16, newGCM, func(key []byte) (cipher.Block, error) { return des.NewCipher(key[:8]) })
	for method, ok := range map[string]bool{"2022-test-block": true, "2022-test-packet-aead": true, "2022-test-bad-block": false} {
		c, err := shadowsocks.NewCipher(method, key)
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok = %v", method, err, ok)
		}
		if _, is2022 := c.(*Cipher); ok && !is2022 {
			t.Errorf("%s: got a %T", method, c)
		}
		if _, err := shadowsocks.NewCipher(method, "password"); err == nil {
			t.Errorf("%s: accepted a key that is not base64", method)
		}
	}
}

// dial returns a client stream and the other end of its transport.
func dial(t *testing.T, c *Cipher) (client, transport net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	client, err := c.ClientConn(a, target)
	if err != nil {
		t.Fatal(err)
	}
	return client, b
}

// accept reads the request from transport and checks its target.
func accept(t *testing.T, c *Cipher, transport net.Conn) net.Conn {
	t.Helper()
	server, addr, err := c.ServerConn(transport)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != target.String() {
		t.Fatalf("target = %v, want %v", addr, target)
	}
	return server
}

func TestStream(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789"), 20000)
	tests := []struct {
		name string
		// first is what the client writes first, nil if it reads first.
		first []byte
	}{
		{"client reads first", nil},
		{"small payload", []byte("hello")},
		{"payload larger than the header", big},
	}
	eachMethod(t, func(t *testing.T, c *Cipher) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, transport := dial(t, c)
				response := make(chan []byte, 1)
				go func() {
					if tt.first != nil {
						client.Write(tt.first)
						client.Write([]byte("ping"))
					}
					got := make([]byte, len(big)+4)
					io.ReadFull(client, got)
					response <- got
				}()

				server := accept(t, c, transport)
				if tt.first != nil {
					want := append(append([]byte{}, tt.first...), "ping"...)
					got := make([]byte, len(want))
					if _, err := io.ReadFull(server, got); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("server read %d bytes that differ from the %d written", len(got), len(want))
					}
				}
				go func() {
					server.Write(big)
					server.Write([]byte("pong"))
				}()
				got := <-response
				if !bytes.Equal(got[:len(big)], big) || string(got[len(big):]) != "pong" {
					t.Fatal("client read a different response")
				}
			})
		}
	})
}

// record returns the bytes a client sends for a request without payload.
func record(t *testing.T, c *Cipher) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	client, err := c.ClientConn(a, target)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		client.Write(nil)
		a.Close()
	}()
	request, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// serve feeds request to a server and returns the error of reading it.
func serve(c *Cipher, request []byte) error {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		a.Write(request)
		a.Close()
	}()
	_, _, err := c.ServerConn(b)
	return err
}

func TestStreamRejects(t *testing.T) {
	eachMethod(t, func(t *testing.T, c *Cipher) {
		request := record(t, c)
		if err := serve(c, request); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if err := serve(c, request); !errors.Is(err, errSaltReplay) {
			t.Fatalf("replay: got %v, want %v", err, errSaltReplay)
		}

		tampered := record(t, c)
		tampered[len(c.key)] ^= 1
		if err := serve(c, tampered); err == nil {
			t.Fatal("tampered header accepted")
		}

		stale := record(t, c)
		c.now = func() time.Time { return time.Now().Add(maxTimeDiff + 5*time.Second) }
		if err := serve(c, stale); !errors.Is(err, errBadTimestamp) {
			t.Fatalf("stale: got %v, want %v", err, errBadTimestamp)
		}
	})
}

func TestStreamResponseBoundToRequest(t *testing.T) {
	eachMethod(t, func(t *testing.T, c *Cipher) {
		// The response to one request must not be accepted for another.
		client1, transport1 := dial(t, c)
		go client1.Write([]byte("ping"))
		server1 := accept(t, c, transport1)

		client2, transport2 := dial(t, c)
		go io.Copy(io.Discard, transport2)
		if _, err := client2.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		// Send the response of the first server to the second client.
		server1.(*serverConn).Conn = transport2
		go server1.Write([]byte("pong"))
		if _, err := client2.Read(make([]byte, 4)); !errors.Is(err, errBadSalt) {
			t.Fatalf("got %v, want %v", err, errBadSalt)
		}
	})
}

// socksTarget is target in the SOCKS format, which starts the plaintext of a packet.
var socksTarget = []byte{0x01, 127, 0, 0, 1, 0, 80}

func packet(payload string) []byte {
	return append(append([]byte{}, socksTarget...), payload...)
}

func TestPacket(t *testing.T) {
	eachMethod(t, func(t *testing.T, c *Cipher) {
		client, err := c.ClientPacket()
		if err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 1024)
		plain := make([]byte, 1024)
		var reply shadowsocks.PacketEncrypter
		for _, msg := range []string{"", "one", "two"} {
			n, err := client.Encrypt(wire, packet(msg))
			if err != nil {
				t.Fatal(err)
			}
			request := append([]byte{}, wire[:n]...)
			n, reply, err = c.ServerPacket(plain, request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain[:n], packet(msg)) {
				t.Fatalf("server got %q", plain[:n])
			}
			if _, _, err := c.ServerPacket(plain, request); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("replayed request: got %v", err)
			}

			n, err = reply.Encrypt(wire, packet("re "+msg))
			if err != nil {
				t.Fatal(err)
			}
			response := append([]byte{}, wire[:n]...)
			n, err = client.Decrypt(plain, response)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain[:n], packet("re "+msg)) {
				t.Fatalf("client got %q", plain[:n])
			}
			if _, err := client.Decrypt(plain, response); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("replayed response: got %v", err)
			}

			// A response is bound to the session of its client.
			other, err := c.ClientPacket()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := other.Decrypt(plain, response); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("response to another session: got %v", err)
			}
			// Requests and responses are not interchangeable.
			if _, err := client.Decrypt(plain, request); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("request as response: got %v", err)
			}
			if _, _, err := c.ServerPacket(plain, response); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("response as request: got %v", err)
			}
		}
		if got := len(c.sessions); got != 1 {
			t.Fatalf("server keeps %d sessions for one client, want 1", got)
		}
	})
}

func TestPacketRejects(t *testing.T) {
	eachMethod(t, func(t *testing.T, c *Cipher) {
		client, err := c.ClientPacket()
		if err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 1024)
		plain := make([]byte, 1024)
		n, err := client.Encrypt(wire, packet("data"))
		if err != nil {
			t.Fatal(err)
		}
		wire = wire[:n]

		if _, err := client.Encrypt(make([]byte, n-1), packet("data")); err != io.ErrShortBuffer {
			t.Fatalf("short encrypt buffer: got %v", err)
		}
		if _, _, err := c.ServerPacket(make([]byte, 8), wire); err != io.ErrShortBuffer {
			t.Fatalf("short decrypt buffer: got %v", err)
		}
		for _, size := range []int{0, 8, 31} {
			if _, _, err := c.ServerPacket(plain, wire[:size]); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
				t.Fatalf("truncated to %d: got %v", size, err)
			}
		}
		tampered := append([]byte{}, wire...)
		tampered[len(tampered)-1] ^= 1
		if _, _, err := c.ServerPacket(plain, tampered); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
			t.Fatalf("tampered: got %v", err)
		}
		if len(c.sessions) != 0 {
			t.Fatal("unauthenticated packet created a session")
		}

		c.now = func() time.Time { return time.Now().Add(maxTimeDiff + 5*time.Second) }
		if _, _, err := c.ServerPacket(plain, wire); !errors.Is(err, shadowsocks.ErrInvalidPacket) {
			t.Fatalf("stale: got %v", err)
		}
	})
}

func TestServerSessionExpires(t *testing.T) {
	eachMethod(t, func(t *testing.T, c *Cipher) {
		now := time.Now()
		c.now = func() time.Time { return now }
		wire := make([]byte, 1024)
		plain := make([]byte, 1024)
		send := func() {
			t.Helper()
			client, err := c.ClientPacket()
			if err != nil {
				t.Fatal(err)
			}
			n, err := client.Encrypt(wire, packet("data"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := c.ServerPacket(plain, wire[:n]); err != nil {
				t.Fatal(err)
			}
		}
		send()
		send()
		now = now.Add(sessionIdle + time.Minute)
		send()
		if got := len(c.sessions); got != 1 {
			t.Fatalf("%d sessions left, want only the live one", got)
		}
	})
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	accept := func(id uint64) bool {
		if !w.valid(id) {
			return false
		}
		w.mark(id)
		return true
	}
	steps := []struct {
		id   uint64
		want bool
	}{
		{0, true},
		{0, false},
		{5, true},
		{3, true},
		{3, false},
		{5, false},
		{replayWindowSize + 4, true},
		{4, false}, // fell out of the window
		{6, true},  // still inside and never seen
		{6, false},
		{10 * replayWindowSize, true},
		{replayWindowSize + 4, false},
		{10*replayWindowSize - 1, true},
		{10*replayWindowSize - replayWindowSize + 1, true},
		{10*replayWindowSize - replayWindowSize, false},
	}
	for i, s := range steps {
		if got := accept(s.id); got != s.want {
			t.Fatalf("step %d: accept(%d) = %v, want %v", i, s.id, got, s.want)
		}
	}
}
