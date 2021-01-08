package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"

	"github.com/wzshiming/shadowsocks"
	"golang.org/x/crypto/hkdf"
)

func RegisterCipher(method string, keyLen int, cipher func(key []byte) (cipher.AEAD, error)) {
	shadowsocks.RegisterCipher(method, func(password string) (shadowsocks.ConnCipher, error) {
		return &Cipher{Rand: rand.Reader, Key: shadowsocks.KDF(password, keyLen), NewAEAD: cipher}, nil
	})
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	io.ReadFull(r, outkey)
}

type Cipher struct {
	Rand    io.Reader
	Key     []byte
	NewAEAD func(key []byte) (cipher.AEAD, error)
}

func (c *Cipher) StreamConn(conn net.Conn) net.Conn {
	return &cipherConn{Conn: conn, cipher: c}
}

func (c *Cipher) KeySize() int {
	return len(c.Key)
}

func (c *Cipher) SaltSize() int {
	if ks := c.KeySize(); ks > 16 {
		return ks
	}
	return 16
}

var sssubkey = []byte("ss-subkey")

func (c *Cipher) Encrypt(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	hkdfSHA1(c.Key, salt, sssubkey, subkey)
	return c.NewAEAD(subkey)
}

func (c *Cipher) Decrypt(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	hkdfSHA1(c.Key, salt, sssubkey, subkey)
	return c.NewAEAD(subkey)
}

func (c *Cipher) initReader(r io.Reader) (*cipherReader, error) {
	salt := make([]byte, c.SaltSize())
	_, err := io.ReadFull(r, salt)
	if err != nil {
		return nil, err
	}
	aead, err := c.Decrypt(salt)
	if err != nil {
		return nil, err
	}
	return newCipherReader(r, aead), nil
}

func (c *Cipher) initWriter(w io.Writer) (*cipherWriter, error) {
	salt := make([]byte, c.SaltSize())
	_, err := io.ReadFull(c.Rand, salt)
	if err != nil {
		return nil, err
	}
	aead, err := c.Encrypt(salt)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(salt)
	if err != nil {
		return nil, err
	}
	return newCipherWriter(w, aead), nil
}

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

type cipherConn struct {
	net.Conn
	cipher *Cipher
	r      *cipherReader
	w      *cipherWriter
}

func (c *cipherConn) Read(b []byte) (n int, err error) {
	if c.r == nil {
		c.r, err = c.cipher.initReader(c.Conn)
		if err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *cipherConn) Write(b []byte) (n int, err error) {
	if c.w == nil {
		c.w, err = c.cipher.initWriter(c.Conn)
		if err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

type cipherWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

// newCipherWriter wraps an io.Writer with AEAD encryption.
func newCipherWriter(w io.Writer, aead cipher.AEAD) *cipherWriter {
	return &cipherWriter{
		w:     w,
		aead:  aead,
		buf:   make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce: make([]byte, aead.NonceSize()),
	}
}

// Write encrypts b and writes to the embedded io.Writer.
func (w *cipherWriter) Write(b []byte) (int, error) {
	overhead := w.aead.Overhead()
	n := 0
	for n < len(b) {
		buf := w.buf
		payloadBuf := buf[2+overhead : 2+overhead+payloadSizeMask]
		nr := copy(payloadBuf, b[n:])
		n += nr
		buf = buf[:2+overhead+nr+overhead]
		payloadBuf = payloadBuf[:nr]
		binary.BigEndian.PutUint16(buf[:2], uint16(nr))
		w.aead.Seal(buf[:0], w.nonce, buf[:2], nil)
		increment(w.nonce)

		w.aead.Seal(payloadBuf[:0], w.nonce, payloadBuf, nil)
		increment(w.nonce)

		_, err := w.w.Write(buf)
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

type cipherReader struct {
	r        io.Reader
	aead     cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte
}

// newCipherReader wraps an io.Reader with AEAD decryption.
func newCipherReader(r io.Reader, aead cipher.AEAD) *cipherReader {
	return &cipherReader{
		r:     r,
		aead:  aead,
		buf:   make([]byte, payloadSizeMask+aead.Overhead()),
		nonce: make([]byte, aead.NonceSize()),
	}
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *cipherReader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	overhead := r.aead.Overhead()
	// decrypt payload size
	buf := r.buf[:2+overhead]
	_, err := io.ReadFull(r.r, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.aead.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	size := int(binary.BigEndian.Uint16(buf[:2]) & payloadSizeMask)

	// decrypt payload
	buf = r.buf[:size+overhead]
	_, err = io.ReadFull(r.r, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.aead.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	m := copy(b, r.buf[:size])
	if m < size { // insufficient len(b), keep leftover for next read
		r.leftover = r.buf[m:size]
	}
	return m, err
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
