package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"

	"github.com/wzshiming/shadowsocks"
	"github.com/wzshiming/shadowsocks/internal/kdf"
	"github.com/wzshiming/shadowsocks/internal/socks"
)

func RegisterCipher(method string, keyLen, ivLen int, encrypt, decrypt func(key, iv []byte) (cipher.Stream, error)) {
	shadowsocks.RegisterCipher(method, func(password string) (shadowsocks.Cipher, error) {
		return &Cipher{
			Rand:       rand.Reader,
			Key:        kdf.KDF(password, keyLen),
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

func (c *Cipher) ClientConn(conn net.Conn, target *shadowsocks.Addr) (net.Conn, error) {
	addr, err := socks.AppendAddr(nil, target)
	if err != nil {
		return nil, err
	}
	conn = &cipherConn{Conn: conn, cipher: c}
	if _, err := conn.Write(addr); err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Cipher) ServerConn(conn net.Conn) (net.Conn, *shadowsocks.Addr, error) {
	conn = &cipherConn{Conn: conn, cipher: c}
	target, err := socks.ReadAddr(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, target, nil
}

// ClientPacket returns the cipher itself: packets are independent of each
// other and requests and responses use the same format.
func (c *Cipher) ClientPacket() (shadowsocks.PacketSession, error) {
	return c, nil
}

func (c *Cipher) ServerPacket(dest, src []byte) (int, shadowsocks.PacketEncrypter, error) {
	n, err := c.Decrypt(dest, src)
	return n, c, err
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

func (c *Cipher) Encrypt(dest, src []byte) (int, error) {
	if len(dest) <= c.IvLen {
		return 0, io.ErrShortBuffer
	}
	iv := dest[:c.IvLen]
	_, err := io.ReadFull(c.Rand, iv)
	if err != nil {
		return 0, err
	}
	enc, err := c.NewEncrypt(c.Key, iv)
	if err != nil {
		return 0, err
	}
	enc.XORKeyStream(dest[c.IvLen:], src)
	return len(src) + c.IvLen, nil
}

func (c *Cipher) Decrypt(dest, src []byte) (int, error) {
	if len(src) <= c.IvLen {
		return 0, shadowsocks.ErrInvalidPacket
	}
	dec, err := c.NewDecrypt(c.Key, src[:c.IvLen])
	if err != nil {
		return 0, err
	}
	dec.XORKeyStream(dest, src[c.IvLen:])
	return len(src) - c.IvLen, nil
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
