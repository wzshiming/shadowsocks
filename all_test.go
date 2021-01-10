package shadowsocks_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wzshiming/shadowsocks"
	_ "github.com/wzshiming/shadowsocks/init"
)

var list = []string{
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
}

func TestAll(t *testing.T) {
	svc := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}))

	pwd := "password"
	for _, c := range list {
		t.Run(c, func(t *testing.T) {
			s, err := shadowsocks.NewSimpleServer("ss://" + c + ":" + pwd + "@:0")
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
