package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"

	"github.com/wzshiming/shadowsocks"
)

func RegisterCipher(method string, keyLen, ivLen int, encrypt, decrypt func(key, iv []byte) (cipher.Stream, error)) {
	shadowsocks.RegisterCipher(method, func(password string) (shadowsocks.ConnCipher, error) {
		return &Cipher{
			Rand:       rand.Reader,
			Key:        shadowsocks.KDF(password, keyLen),
			IvLen:      ivLen,
			NewEncrypt: encrypt,
			NewDecrypt: decrypt,
		}, nil
	})
}

type Cipher struct {
	Rand       io.Reader
	Key        []byte
	IvLen      int
	NewDecrypt func(key, iv []byte) (cipher.Stream, error)
	NewEncrypt func(key, iv []byte) (cipher.Stream, error)
}

func (c *Cipher) initEncrypt(w io.Writer) (cipher.Stream, error) {
	iv := make([]byte, c.IvLen)
	_, err := io.ReadFull(c.Rand, iv)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(iv)
	if err != nil {
		return nil, err
	}
	return c.NewEncrypt(c.Key, iv)
}

func (c *Cipher) initDecrypt(r io.Reader) (cipher.Stream, error) {
	iv := make([]byte, c.IvLen)
	_, err := io.ReadFull(r, iv)
	if err != nil {
		return nil, err
	}
	return c.NewDecrypt(c.Key, iv)
}

func (c *Cipher) StreamConn(conn net.Conn) net.Conn {
	return &cipherConn{
		Conn:   conn,
		cipher: c,
	}
}

type cipherConn struct {
	cipher *Cipher
	net.Conn
	enc cipher.Stream
	dec cipher.Stream
}

func (c *cipherConn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		c.dec, err = c.cipher.initDecrypt(c.Conn)
		if err != nil {
			return 0, err
		}
	}
	n, err = c.Conn.Read(b)
	if err != nil {
		return 0, err
	}
	c.dec.XORKeyStream(b, b[:n])
	return n, nil
}

func (c *cipherConn) Write(b []byte) (n int, err error) {
	if c.enc == nil {
		c.enc, err = c.cipher.initEncrypt(c.Conn)
		if err != nil {
			return 0, err
		}
	}
	c.enc.XORKeyStream(b, b)
	return c.Conn.Write(b)
}
