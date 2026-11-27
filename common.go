package shadowsocks

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
)

// isClosedConnError reports whether err is an error from use of a closed
// network connection.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}

	if runtime.GOOS == "windows" {
		if oe, ok := err.(*net.OpError); ok && oe.Op == "read" {
			if se, ok := oe.Err.(*os.SyscallError); ok && se.Syscall == "wsarecv" {
				const WSAECONNABORTED = 10053
				const WSAECONNRESET = 10054
				if n := errno(se.Err); n == WSAECONNRESET || n == WSAECONNABORTED {
					return true
				}
			}
		}
	}
	return false
}

func errno(v error) uintptr {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Uintptr {
		return uintptr(rv.Uint())
	}
	return 0
}

// errTunnelDone is used to stop the tunnel without waiting for the other direction.
var errTunnelDone = errors.New("tunnel done")

type closeWriter interface {
	CloseWrite() error
}

// tunnel create tunnels for two io.ReadWriteCloser.
// When one of them is done with sending, the other one is notified by
// shutting down the writing side of it if that is supported, and the
// data in the other direction is still relayed until that is done too.
func tunnel(ctx context.Context, c1, c2 io.ReadWriteCloser, buf1, buf2 []byte) error {
	errCh := make(chan error, 2)
	go func() {
		errCh <- relay(c1, c2, buf1)
	}()
	go func() {
		errCh <- relay(c2, c1, buf2)
	}()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	for i := 0; i != 2; i++ {
		select {
		case err := <-errCh:
			if err == errTunnelDone {
				return nil
			}
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func relay(dst io.Writer, src io.Reader, buf []byte) error {
	_, err := io.CopyBuffer(dst, src, buf)
	if err != nil {
		return err
	}
	if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
		return nil
	}
	return errTunnelDone
}

// BytesPool is an interface for getting and returning temporary
// bytes for use by io.CopyBuffer.
type BytesPool interface {
	Get() []byte
	Put([]byte)
}

func getBytes(p BytesPool) []byte {
	if p != nil {
		return p.Get()
	}
	return make([]byte, 32*1024)
}

func putBytes(p BytesPool, d []byte) {
	if p != nil {
		p.Put(d)
	}
}

func decodeCipherAndPasswordFromBase64(str string) (cipher, password string, err error) {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", "", fmt.Errorf("can't support %q", str)
	}
	cp := strings.SplitN(string(data), ":", 2)
	if len(cp) != 2 {
		return cp[0], "", nil
	}
	return cp[0], cp[1], nil
}

func GetCipherAndPasswordFromUserinfo(user *url.Userinfo) (cipher, password string, err error) {
	cipher = user.Username()
	password, ok := user.Password()
	if !ok && !IsCipher(cipher) {
		cipher, password, err = decodeCipherAndPasswordFromBase64(cipher)
		if err != nil {
			return "", "", err
		}
	}
	return cipher, password, nil
}

type proxyConfig struct {
	Address    string
	Cipher     string
	Password   string
	ConnCipher ConnCipher
}

// parseProxyURL parses an ss:// URL into address, cipher and password.
func parseProxyURL(addr string) (*proxyConfig, error) {
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
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "8379")
	}
	var cfg proxyConfig
	if u.User != nil {
		cfg.Cipher, cfg.Password, err = GetCipherAndPasswordFromUserinfo(u.User)
		if err != nil {
			return nil, err
		}
	}
	connCipher, err := NewCipher(cfg.Cipher, cfg.Password)
	if err != nil {
		return nil, err
	}
	cfg.ConnCipher = connCipher
	cfg.Address = host
	return &cfg, nil
}

type Logger interface {
	Println(v ...interface{})
}
