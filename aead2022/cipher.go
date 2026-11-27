// Package aead2022 implements the Shadowsocks 2022 (SIP022) protocol. The
// ciphers themselves are registered by its sub-packages.
//
// Unlike the earlier AEAD ciphers, the key is a base64 encoded pre-shared key
// of exactly the cipher's key size, requests and responses use different
// formats, and both directions are protected against replay.
package aead2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wzshiming/shadowsocks"
	"github.com/wzshiming/shadowsocks/internal/socks"
	"lukechampine.com/blake3"
)

const (
	headerTypeClient = 0
	headerTypeServer = 1

	// maxTimeDiff is the largest accepted difference between the timestamp of
	// a header and the local clock.
	maxTimeDiff = 30 * time.Second
	// saltLifetime is how long a request salt is remembered to reject replays.
	// It must cover the whole window in which a timestamp is accepted.
	saltLifetime = 2 * maxTimeDiff

	subkeyContext = "shadowsocks 2022 session subkey"
)

var (
	errBadHeaderType = errors.New("shadowsocks 2022: bad header type")
	errBadTimestamp  = errors.New("shadowsocks 2022: timestamp is too far from the local time")
	errSaltReplay    = errors.New("shadowsocks 2022: salt is not unique")
	errBadSalt       = errors.New("shadowsocks 2022: response does not match the request salt")
	errNoPadding     = errors.New("shadowsocks 2022: request has neither payload nor padding")
	errBadHeader     = errors.New("shadowsocks 2022: malformed header")
)

// RegisterCipher registers a cipher under method.
//
// newAEAD seals TCP streams and the body of UDP packets, with a subkey derived
// for each stream and each UDP session. newBlock encrypts the separate header
// of UDP packets with the key itself, its block size must be 16 bytes.
func RegisterCipher(method string, keyLen int, newAEAD func(key []byte) (cipher.AEAD, error), newBlock func(key []byte) (cipher.Block, error)) {
	register(method, keyLen, func(key []byte) (*Cipher, error) {
		block, err := newBlock(key)
		if err != nil {
			return nil, err
		}
		if block.BlockSize() != packetHeaderSize {
			return nil, fmt.Errorf("block size must be %d bytes, got %d", packetHeaderSize, block.BlockSize())
		}
		return newCipher(key, newAEAD, block, nil), nil
	})
}

// RegisterPacketAEADCipher registers a cipher under method whose UDP packets
// have no separate header.
//
// newAEAD seals TCP streams with a subkey derived for each stream.
// newPacketAEAD seals whole UDP packets with the key itself and a random
// nonce, so its nonce must be large enough to be picked at random.
func RegisterPacketAEADCipher(method string, keyLen int, newAEAD, newPacketAEAD func(key []byte) (cipher.AEAD, error)) {
	register(method, keyLen, func(key []byte) (*Cipher, error) {
		packetAEAD, err := newPacketAEAD(key)
		if err != nil {
			return nil, err
		}
		return newCipher(key, newAEAD, nil, packetAEAD), nil
	})
}

func register(method string, keyLen int, build func(key []byte) (*Cipher, error)) {
	shadowsocks.RegisterCipher(method, func(password string) (shadowsocks.Cipher, error) {
		key, err := decodeKey(password, keyLen)
		if err == nil {
			var c *Cipher
			if c, err = build(key); err == nil {
				return c, nil
			}
		}
		return nil, fmt.Errorf("%s: %w", method, err)
	})
}

// decodeKey decodes the base64 pre-shared key and checks its size.
func decodeKey(password string, keyLen int) ([]byte, error) {
	if strings.Contains(password, ":") {
		return nil, errors.New("multi-user keys (iPSK:uPSK) are not supported")
	}
	key, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(password)
	}
	if err != nil {
		return nil, fmt.Errorf("key must be base64 encoded: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", keyLen, len(key))
	}
	return key, nil
}

// Cipher is a Shadowsocks 2022 cipher.
type Cipher struct {
	key     []byte
	newAEAD func(key []byte) (cipher.AEAD, error)
	rand    io.Reader
	now     func() time.Time

	// UDP: a cipher either encrypts the separate header with block,
	// or seals the whole packet with packetAEAD.
	block      cipher.Block
	packetAEAD cipher.AEAD

	saltMut   sync.Mutex
	salts     map[string]time.Time
	saltPurge time.Time

	sessionMut   sync.Mutex
	sessions     map[uint64]*serverSession
	sessionPurge time.Time
}

func newCipher(key []byte, newAEAD func(key []byte) (cipher.AEAD, error), block cipher.Block, packetAEAD cipher.AEAD) *Cipher {
	return &Cipher{
		key:        key,
		newAEAD:    newAEAD,
		rand:       rand.Reader,
		now:        time.Now,
		block:      block,
		packetAEAD: packetAEAD,
		salts:      map[string]time.Time{},
		sessions:   map[uint64]*serverSession{},
	}
}

// sessionAEAD derives the subkey of a TCP stream or a UDP session.
func (c *Cipher) sessionAEAD(salt []byte) (cipher.AEAD, error) {
	material := make([]byte, 0, len(c.key)+len(salt))
	material = append(material, c.key...)
	material = append(material, salt...)
	subkey := make([]byte, len(c.key))
	blake3.DeriveKey(subkey, subkeyContext, material)
	return c.newAEAD(subkey)
}

func (c *Cipher) checkTimestamp(ts uint64) error {
	diff := c.now().Unix() - int64(ts)
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(maxTimeDiff/time.Second) {
		return errBadTimestamp
	}
	return nil
}

// checkSalt records the salt of an authenticated request, rejecting replays.
func (c *Cipher) checkSalt(salt []byte) error {
	now := c.now()
	c.saltMut.Lock()
	defer c.saltMut.Unlock()
	if now.Sub(c.saltPurge) > saltLifetime {
		for s, t := range c.salts {
			if now.Sub(t) > saltLifetime {
				delete(c.salts, s)
			}
		}
		c.saltPurge = now
	}
	if t, ok := c.salts[string(salt)]; ok && now.Sub(t) <= saltLifetime {
		return errSaltReplay
	}
	c.salts[string(salt)] = now
	return nil
}

// ClientConn wraps a connection to a server into a connection to target.
// The request is sent with the first write so that it carries payload, or
// with the first read if the server is expected to speak first.
func (c *Cipher) ClientConn(conn net.Conn, target *shadowsocks.Addr) (net.Conn, error) {
	addr, err := socks.AppendAddr(nil, target)
	if err != nil {
		return nil, err
	}
	return &clientConn{Conn: conn, cipher: c, target: addr}, nil
}

// ServerConn reads the request of a client. It returns the target and a
// connection carrying the payload.
func (c *Cipher) ServerConn(conn net.Conn) (net.Conn, *shadowsocks.Addr, error) {
	stream, target, err := c.readRequest(conn)
	if err != nil {
		return nil, nil, err
	}
	return stream, target, nil
}
