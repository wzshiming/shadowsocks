package shadowsocks_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wzshiming/shadowsocks"
	_ "github.com/wzshiming/shadowsocks/init"
)

var list = []string{
	"dummy",
	"aes-128-cfb",
	"aes-128-ctr",
	"aes-128-gcm",
	"aes-192-cfb",
	"aes-192-ctr",
	"aes-256-cfb",
	"aes-256-ctr",
	"aes-256-gcm",
	"bf-cfb",
	"cast5-cfb",
	"chacha20",
	"chacha20-ietf",
	"chacha20-ietf-poly1305",
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
	"aes-256-cfb:123",
	"aes-256-ctr:123",
	"aes-256-gcm:123",
	"bf-cfb:123",
	"cast5-cfb:123",
	"chacha20:123",
	"chacha20-ietf:123",
	"chacha20-ietf-poly1305:123",
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
