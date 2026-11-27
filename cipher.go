package shadowsocks

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ErrInvalidPacket marks malformed datagrams that packet readers may discard.
var ErrInvalidPacket = errors.New("shadowsocks: invalid packet")

// Cipher is the cipher of a method. Clients and servers use different
// methods of it, as a protocol may distinguish requests from responses.
type Cipher interface {
	// ClientConn wraps a connection to a server into a connection to target.
	ClientConn(conn net.Conn, target *Addr) (net.Conn, error)
	// ServerConn reads the request of a client from an accepted connection.
	// It returns the target and a connection carrying the payload.
	ServerConn(conn net.Conn) (net.Conn, *Addr, error)

	// ClientPacket starts a client UDP session, which encrypts requests and
	// decrypts the responses to them.
	ClientPacket() (PacketSession, error)
	// ServerPacket decrypts a request on the server. The returned encrypter
	// builds the responses for the session the request belongs to.
	ServerPacket(dist, src []byte) (n int, reply PacketEncrypter, err error)
}

// PacketEncrypter encrypts UDP packets. The plaintext of a packet is the
// SOCKS address of the target followed by the payload.
type PacketEncrypter interface {
	Encrypt(dist, src []byte) (n int, err error)
}

// PacketDecrypter decrypts UDP packets into the SOCKS address of the target
// followed by the payload.
type PacketDecrypter interface {
	Decrypt(dist, src []byte) (n int, err error)
}

// PacketSession is the client side of a UDP session.
type PacketSession interface {
	PacketEncrypter
	PacketDecrypter
}

var registerCipher = map[string]func(password string) (Cipher, error){}

func formatMethod(method string) string {
	return strings.ToLower(strings.ReplaceAll(method, "_", "-"))
}

func RegisterCipher(method string, fun func(password string) (Cipher, error)) {
	registerCipher[formatMethod(method)] = fun
}

func CipherList() []string {
	list := make([]string, 0, len(registerCipher))
	for name := range registerCipher {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func IsCipher(method string) bool {
	_, ok := registerCipher[formatMethod(method)]
	return ok
}

// NewCipher creates a cipher that can be used in Dial()
func NewCipher(method, password string) (c Cipher, err error) {
	gen, ok := registerCipher[formatMethod(method)]
	if ok {
		return gen(password)
	}
	return nil, fmt.Errorf("unsupported encryption method: %s", method)
}
