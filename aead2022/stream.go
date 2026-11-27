package aead2022

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/wzshiming/shadowsocks"
	"github.com/wzshiming/shadowsocks/internal/socks"
)

const (
	// maxChunkSize is the largest payload of a chunk and of the
	// variable-length request header.
	maxChunkSize = 0xFFFF
	// maxPadding is the largest padding added to a request without payload.
	maxPadding = 900
	// fixedRequestHeaderSize is type + timestamp + length.
	fixedRequestHeaderSize = 1 + 8 + 2
)

// clientConn is the client side of a stream. The request header is sent with
// the first write so that it carries payload, or with the first read if the
// server is expected to speak first.
type clientConn struct {
	net.Conn
	cipher *Cipher
	// target is the SOCKS address of the target.
	target []byte

	// mut guards sending the request, which reads and writes may both start.
	mut         sync.Mutex
	w           *chunkWriter
	werr        error
	requestSalt []byte

	r    *chunkReader
	rerr error
}

// request sends the request header with payload, unless it was sent already.
func (c *clientConn) request(payload []byte) (sent bool, err error) {
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.w != nil || c.werr != nil {
		return false, c.werr
	}
	c.werr = c.writeRequest(payload)
	return true, c.werr
}

func (c *clientConn) Write(b []byte) (int, error) {
	sent, err := c.request(b)
	if err != nil {
		return 0, err
	}
	if sent {
		return len(b), nil
	}
	return c.w.Write(b)
}

func (c *clientConn) Read(b []byte) (int, error) {
	if c.rerr != nil {
		return 0, c.rerr
	}
	if c.r == nil {
		if _, c.rerr = c.request(nil); c.rerr != nil {
			return 0, c.rerr
		}
		if c.r, c.rerr = c.readResponse(); c.rerr != nil {
			return 0, c.rerr
		}
	}
	n, err := c.r.Read(b)
	if err != nil {
		c.rerr = err
	}
	return n, err
}

func (c *clientConn) writeRequest(payload []byte) error {
	salt := make([]byte, len(c.cipher.key))
	if _, err := io.ReadFull(c.cipher.rand, salt); err != nil {
		return err
	}
	var rest []byte
	if max := maxChunkSize - len(c.target) - 2; len(payload) > max {
		payload, rest = payload[:max], payload[max:]
	}
	// A request without payload must be padded.
	padding := 0
	if len(payload) == 0 {
		var r [2]byte
		if _, err := io.ReadFull(c.cipher.rand, r[:]); err != nil {
			return err
		}
		padding = 1 + int(binary.BigEndian.Uint16(r[:]))%maxPadding
	}

	aead, err := c.cipher.sessionAEAD(salt)
	if err != nil {
		return err
	}
	w := newChunkWriter(c.Conn, aead)

	variable := make([]byte, 0, len(c.target)+2+padding+len(payload))
	variable = append(variable, c.target...)
	variable = binary.BigEndian.AppendUint16(variable, uint16(padding))
	variable = append(variable, make([]byte, padding)...)
	variable = append(variable, payload...)

	fixed := make([]byte, 0, fixedRequestHeaderSize)
	fixed = append(fixed, headerTypeClient)
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(c.cipher.now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))

	out := make([]byte, 0, len(salt)+len(fixed)+len(variable)+2*aead.Overhead())
	out = append(out, salt...)
	out = w.seal(out, fixed)
	out = w.seal(out, variable)
	if _, err := c.Conn.Write(out); err != nil {
		return err
	}
	if len(rest) > 0 {
		if _, err := w.Write(rest); err != nil {
			return err
		}
	}
	c.requestSalt = salt
	c.w = w
	return nil
}

// readResponse reads the response header and its first payload chunk.
func (c *clientConn) readResponse() (*chunkReader, error) {
	saltLen := len(c.cipher.key)
	head := make([]byte, saltLen+1+8+saltLen+2+16)
	if _, err := io.ReadFull(c.Conn, head); err != nil {
		return nil, err
	}
	aead, err := c.cipher.sessionAEAD(head[:saltLen])
	if err != nil {
		return nil, err
	}
	r := newChunkReader(c.Conn, aead)
	fixed, err := r.open(head[saltLen:])
	if err != nil {
		return nil, err
	}
	if fixed[0] != headerTypeServer {
		return nil, errBadHeaderType
	}
	if err := c.cipher.checkTimestamp(binary.BigEndian.Uint64(fixed[1:])); err != nil {
		return nil, err
	}
	c.mut.Lock()
	requestSalt := c.requestSalt
	c.mut.Unlock()
	if !bytes.Equal(fixed[9:9+saltLen], requestSalt) {
		return nil, errBadSalt
	}
	r.leftover, err = r.readChunk(int(binary.BigEndian.Uint16(fixed[9+saltLen:])))
	if err != nil {
		return nil, err
	}
	return r, nil
}

// serverConn is the server side of a stream whose request was read.
type serverConn struct {
	net.Conn
	cipher      *Cipher
	requestSalt []byte
	r           *chunkReader
	w           *chunkWriter
}

func (c *serverConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *serverConn) Write(b []byte) (int, error) {
	if c.w != nil {
		return c.w.Write(b)
	}
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.writeResponse(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// writeResponse sends the response header together with the first payload chunk.
func (c *serverConn) writeResponse(b []byte) error {
	salt := make([]byte, len(c.cipher.key))
	if _, err := io.ReadFull(c.cipher.rand, salt); err != nil {
		return err
	}
	aead, err := c.cipher.sessionAEAD(salt)
	if err != nil {
		return err
	}
	w := newChunkWriter(c.Conn, aead)

	first := b
	if len(first) > maxChunkSize {
		first = first[:maxChunkSize]
	}
	fixed := make([]byte, 0, 1+8+len(c.requestSalt)+2)
	fixed = append(fixed, headerTypeServer)
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(c.cipher.now().Unix()))
	fixed = append(fixed, c.requestSalt...)
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(first)))

	out := make([]byte, 0, len(salt)+len(fixed)+len(first)+2*aead.Overhead())
	out = append(out, salt...)
	out = w.seal(out, fixed)
	out = w.seal(out, first)
	if _, err := c.Conn.Write(out); err != nil {
		return err
	}
	c.w = w
	if len(b) > len(first) {
		_, err = w.Write(b[len(first):])
	}
	return err
}

// readRequest reads the request header of a client. It returns the target
// and a connection carrying the payload.
func (c *Cipher) readRequest(conn net.Conn) (*serverConn, *shadowsocks.Addr, error) {
	saltLen := len(c.key)
	head := make([]byte, saltLen+fixedRequestHeaderSize+16)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, nil, err
	}
	salt := head[:saltLen]
	aead, err := c.sessionAEAD(salt)
	if err != nil {
		return nil, nil, err
	}
	r := newChunkReader(conn, aead)
	fixed, err := r.open(head[saltLen:])
	if err != nil {
		return nil, nil, err
	}
	if fixed[0] != headerTypeClient {
		return nil, nil, errBadHeaderType
	}
	if err := c.checkTimestamp(binary.BigEndian.Uint64(fixed[1:])); err != nil {
		return nil, nil, err
	}
	if err := c.checkSalt(salt); err != nil {
		return nil, nil, err
	}

	chunk, err := r.readChunk(int(binary.BigEndian.Uint16(fixed[9:])))
	if err != nil {
		return nil, nil, err
	}
	variable := bytes.NewReader(chunk)
	target, err := socks.ReadAddr(variable)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errBadHeader, err)
	}
	rest := chunk[len(chunk)-variable.Len():]
	if len(rest) < 2 {
		return nil, nil, errBadHeader
	}
	padding := int(binary.BigEndian.Uint16(rest))
	if len(rest) < 2+padding {
		return nil, nil, errBadHeader
	}
	payload := rest[2+padding:]
	if padding == 0 && len(payload) == 0 {
		return nil, nil, errNoPadding
	}
	r.leftover = payload
	return &serverConn{Conn: conn, cipher: c, requestSalt: salt, r: r}, target, nil
}

type chunkWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

func newChunkWriter(w io.Writer, aead cipher.AEAD) *chunkWriter {
	return &chunkWriter{w: w, aead: aead, nonce: make([]byte, aead.NonceSize())}
}

// seal appends the encrypted plaintext to dst and advances the nonce.
func (w *chunkWriter) seal(dst, plaintext []byte) []byte {
	dst = w.aead.Seal(dst, w.nonce, plaintext, nil)
	increment(w.nonce)
	return dst
}

// Write sends b as length and payload chunks.
func (w *chunkWriter) Write(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		chunk := b[n:]
		if len(chunk) > maxChunkSize {
			chunk = chunk[:maxChunkSize]
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(chunk)))
		w.buf = w.seal(w.buf[:0], size[:])
		w.buf = w.seal(w.buf, chunk)
		if _, err := w.w.Write(w.buf); err != nil {
			return n, err
		}
		n += len(chunk)
	}
	return n, nil
}

type chunkReader struct {
	r        io.Reader
	aead     cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte
}

func newChunkReader(r io.Reader, aead cipher.AEAD) *chunkReader {
	return &chunkReader{r: r, aead: aead, nonce: make([]byte, aead.NonceSize())}
}

// open decrypts sealed in place and advances the nonce.
func (r *chunkReader) open(sealed []byte) ([]byte, error) {
	plaintext, err := r.aead.Open(sealed[:0], r.nonce, sealed, nil)
	increment(r.nonce)
	return plaintext, err
}

// readChunk reads and decrypts a chunk of size plaintext bytes. The result is
// only valid until the next call.
func (r *chunkReader) readChunk(size int) ([]byte, error) {
	sealed := size + r.aead.Overhead()
	if cap(r.buf) < sealed {
		r.buf = make([]byte, sealed)
	}
	buf := r.buf[:sealed]
	if _, err := io.ReadFull(r.r, buf); err != nil {
		return nil, err
	}
	return r.open(buf)
}

func (r *chunkReader) Read(b []byte) (int, error) {
	for len(r.leftover) == 0 {
		var head [2 + 16]byte
		if _, err := io.ReadFull(r.r, head[:]); err != nil {
			return 0, err
		}
		size, err := r.open(head[:])
		if err != nil {
			return 0, err
		}
		r.leftover, err = r.readChunk(int(binary.BigEndian.Uint16(size)))
		if err != nil {
			return 0, err
		}
	}
	n := copy(b, r.leftover)
	r.leftover = r.leftover[n:]
	return n, nil
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
