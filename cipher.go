package shadowsocks

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

var (
	errEmptyPassword = errors.New("empty key")
)

type ConnCipher interface {
	StreamConn(net.Conn) net.Conn
}

var registerCipher = map[string]func(password string) (ConnCipher, error){}

func RegisterCipher(method string, fun func(password string) (ConnCipher, error)) {
	registerCipher[strings.ToLower(method)] = fun
}

func CipherList() []string {
	list := make([]string, 0, len(registerCipher))
	for name := range registerCipher {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

// NewCipher creates a cipher that can be used in Dial()
func NewCipher(method, password string) (c ConnCipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	method = strings.ToLower(method)
	gen, ok := registerCipher[method]
	if ok {
		return gen(password)
	}
	return nil, fmt.Errorf("unsupported encryption method: %s", method)
}

// key-derivation function from original Shadowsocks
func KDF(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
