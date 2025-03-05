package shadowsocks

import (
	"context"
	"encoding/base64"
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

// tunnel create tunnels for two io.ReadWriteCloser
func tunnel(ctx context.Context, c1, c2 io.ReadWriteCloser, buf1, buf2 []byte) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.CopyBuffer(c1, c2, buf1)
		errCh <- err
	}()
	go func() {
		_, err := io.CopyBuffer(c2, c1, buf2)
		errCh <- err
	}()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
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

type Logger interface {
	Println(v ...interface{})
}
