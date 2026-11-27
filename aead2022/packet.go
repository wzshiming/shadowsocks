package aead2022

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wzshiming/shadowsocks"
)

const (
	// packetHeaderSize is session ID + packet ID.
	packetHeaderSize = 16
	tagSize          = 16
	// sessionIdle is how long the server keeps a UDP session without traffic.
	sessionIdle = 5 * time.Minute
)

func invalidPacket(reason string) error {
	return fmt.Errorf("%w: %s", shadowsocks.ErrInvalidPacket, reason)
}

// sealPacket writes a packet carrying meta and payload to dist. aead is the
// subkey of the sending session, unused by a cipher that seals whole packets.
func (c *Cipher) sealPacket(dist []byte, aead cipher.AEAD, sessionID, packetID uint64, meta, payload []byte) (int, error) {
	prefix := 0
	if c.packetAEAD != nil {
		prefix = c.packetAEAD.NonceSize()
	}
	total := prefix + packetHeaderSize + len(meta) + len(payload) + tagSize
	if len(dist) < total {
		return 0, io.ErrShortBuffer
	}
	p := dist[prefix:prefix]
	p = binary.BigEndian.AppendUint64(p, sessionID)
	p = binary.BigEndian.AppendUint64(p, packetID)
	p = append(p, meta...)
	p = append(p, payload...)
	if c.packetAEAD != nil {
		nonce := dist[:prefix]
		if _, err := io.ReadFull(c.rand, nonce); err != nil {
			return 0, err
		}
		c.packetAEAD.Seal(p[:0], nonce, p, nil)
		return total, nil
	}
	var nonce [12]byte
	copy(nonce[:], p[4:packetHeaderSize])
	aead.Seal(p[packetHeaderSize:packetHeaderSize], nonce[:], p[packetHeaderSize:], nil)
	c.block.Encrypt(p[:packetHeaderSize], p[:packetHeaderSize])
	return total, nil
}

// openPacket decrypts src into dest and returns the IDs of the packet and its
// body. aeadFor returns the subkey of the sending session, it is not called by
// a cipher that seals whole packets.
func (c *Cipher) openPacket(dest, src []byte, aeadFor func(sessionID uint64) (cipher.AEAD, error)) (sessionID, packetID uint64, body []byte, err error) {
	if c.packetAEAD != nil {
		prefix := c.packetAEAD.NonceSize()
		if len(src) < prefix+packetHeaderSize+tagSize {
			return 0, 0, nil, invalidPacket("too short")
		}
		if len(dest) < len(src) {
			return 0, 0, nil, io.ErrShortBuffer
		}
		p, err := c.packetAEAD.Open(dest[:0], src[:prefix], src[prefix:], nil)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("%w: %w", shadowsocks.ErrInvalidPacket, err)
		}
		return binary.BigEndian.Uint64(p), binary.BigEndian.Uint64(p[8:]), p[packetHeaderSize:], nil
	}
	if len(src) < packetHeaderSize+tagSize {
		return 0, 0, nil, invalidPacket("too short")
	}
	if len(dest) < len(src) {
		return 0, 0, nil, io.ErrShortBuffer
	}
	var header [packetHeaderSize]byte
	c.block.Decrypt(header[:], src[:packetHeaderSize])
	sessionID = binary.BigEndian.Uint64(header[:])
	packetID = binary.BigEndian.Uint64(header[8:])
	aead, err := aeadFor(sessionID)
	if err != nil {
		return 0, 0, nil, err
	}
	body, err = aead.Open(dest[:0], header[4:], src[packetHeaderSize:], nil)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: %w", shadowsocks.ErrInvalidPacket, err)
	}
	return sessionID, packetID, body, nil
}

// packetMeta builds the fields between the packet header and the address.
// No padding is added.
func (c *Cipher) packetMeta(buf []byte, typ byte, clientSession uint64) []byte {
	buf = append(buf, typ)
	buf = binary.BigEndian.AppendUint64(buf, uint64(c.now().Unix()))
	if typ == headerTypeServer {
		buf = binary.BigEndian.AppendUint64(buf, clientSession)
	}
	return append(buf, 0, 0)
}

// parsePacketBody validates the fields of a body and returns what follows
// them: the address and the payload.
func (c *Cipher) parsePacketBody(body []byte, typ byte) (clientSession uint64, rest []byte, err error) {
	size := 1 + 8 + 2
	if typ == headerTypeServer {
		size += 8
	}
	if len(body) < size {
		return 0, nil, invalidPacket("truncated header")
	}
	if body[0] != typ {
		return 0, nil, invalidPacket("bad header type")
	}
	if err := c.checkTimestamp(binary.BigEndian.Uint64(body[1:])); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", shadowsocks.ErrInvalidPacket, err)
	}
	if typ == headerTypeServer {
		clientSession = binary.BigEndian.Uint64(body[9:])
	}
	padding := int(binary.BigEndian.Uint16(body[size-2:]))
	if len(body) < size+padding {
		return 0, nil, invalidPacket("truncated padding")
	}
	return clientSession, body[size+padding:], nil
}

func (c *Cipher) randomID() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(c.rand, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// packetSessionAEAD derives the subkey of a UDP session, nil for a cipher
// that seals whole packets and so has no session subkeys.
func (c *Cipher) packetSessionAEAD(sessionID uint64) (cipher.AEAD, error) {
	if c.packetAEAD != nil {
		return nil, nil
	}
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], sessionID)
	return c.sessionAEAD(salt[:])
}

// ClientPacket starts a client UDP session: Encrypt builds requests and
// Decrypt opens the responses to them.
func (c *Cipher) ClientPacket() (shadowsocks.PacketSession, error) {
	id, err := c.randomID()
	if err != nil {
		return nil, err
	}
	aead, err := c.packetSessionAEAD(id)
	if err != nil {
		return nil, err
	}
	return &clientSession{cipher: c, id: id, aead: aead}, nil
}

type clientSession struct {
	cipher   *Cipher
	id       uint64
	aead     cipher.AEAD
	packetID atomic.Uint64

	mut sync.Mutex
	// remotes are the current and the previous session of the server, which
	// starts a new one when it restarts or drops an idle session.
	remotes [2]*remoteSession
}

type remoteSession struct {
	id     uint64
	aead   cipher.AEAD
	window replayWindow
}

func (s *clientSession) remote(id uint64) *remoteSession {
	for _, r := range s.remotes {
		if r != nil && r.id == id {
			return r
		}
	}
	return nil
}

func (s *clientSession) Encrypt(dist, src []byte) (int, error) {
	var buf [1 + 8 + 2]byte
	meta := s.cipher.packetMeta(buf[:0], headerTypeClient, 0)
	return s.cipher.sealPacket(dist, s.aead, s.id, s.packetID.Add(1)-1, meta, src)
}

func (s *clientSession) Decrypt(dist, src []byte) (int, error) {
	var aead cipher.AEAD
	remoteID, packetID, body, err := s.cipher.openPacket(dist, src, func(id uint64) (cipher.AEAD, error) {
		s.mut.Lock()
		r := s.remote(id)
		s.mut.Unlock()
		if r != nil {
			aead = r.aead
			return aead, nil
		}
		var err error
		aead, err = s.cipher.packetSessionAEAD(id)
		return aead, err
	})
	if err != nil {
		return 0, err
	}
	clientID, rest, err := s.cipher.parsePacketBody(body, headerTypeServer)
	if err != nil {
		return 0, err
	}
	if clientID != s.id {
		return 0, invalidPacket("response to another session")
	}

	s.mut.Lock()
	r := s.remote(remoteID)
	if r == nil {
		r = &remoteSession{id: remoteID, aead: aead}
		s.remotes[1] = s.remotes[0]
		s.remotes[0] = r
	}
	fresh := r.window.valid(packetID)
	if fresh {
		r.window.mark(packetID)
	}
	s.mut.Unlock()
	if !fresh {
		return 0, invalidPacket("replayed packet")
	}
	return copy(dist, rest), nil
}

// ServerPacket opens a request as a server. The returned encrypter builds
// the responses for the session the request belongs to.
func (c *Cipher) ServerPacket(dist, src []byte) (int, shadowsocks.PacketEncrypter, error) {
	var sess *serverSession
	var aead cipher.AEAD
	clientID, packetID, body, err := c.openPacket(dist, src, func(id uint64) (cipher.AEAD, error) {
		if sess = c.serverSession(id); sess != nil {
			return sess.clientAEAD, nil
		}
		var err error
		aead, err = c.packetSessionAEAD(id)
		return aead, err
	})
	if err != nil {
		return 0, nil, err
	}
	_, rest, err := c.parsePacketBody(body, headerTypeClient)
	if err != nil {
		return 0, nil, err
	}
	if sess == nil {
		sess = c.serverSession(clientID)
	}
	if sess == nil {
		sess, err = c.newServerSession(clientID, aead)
		if err != nil {
			return 0, nil, err
		}
	}
	if !sess.accept(packetID) {
		return 0, nil, invalidPacket("replayed packet")
	}
	return copy(dist, rest), sess, nil
}

// serverSession returns the live session of a client, nil if there is none.
func (c *Cipher) serverSession(clientID uint64) *serverSession {
	c.sessionMut.Lock()
	defer c.sessionMut.Unlock()
	sess := c.sessions[clientID]
	if sess != nil {
		sess.last = c.now()
	}
	return sess
}

// newServerSession registers the session of a client whose first packet was
// authenticated, unless another packet of it got there first.
func (c *Cipher) newServerSession(clientID uint64, clientAEAD cipher.AEAD) (*serverSession, error) {
	id, err := c.randomID()
	if err != nil {
		return nil, err
	}
	aead, err := c.packetSessionAEAD(id)
	if err != nil {
		return nil, err
	}
	now := c.now()
	c.sessionMut.Lock()
	defer c.sessionMut.Unlock()
	if now.Sub(c.sessionPurge) > time.Minute {
		for id, sess := range c.sessions {
			if now.Sub(sess.last) > sessionIdle {
				delete(c.sessions, id)
			}
		}
		c.sessionPurge = now
	}
	if sess := c.sessions[clientID]; sess != nil {
		sess.last = now
		return sess, nil
	}
	sess := &serverSession{
		cipher:     c,
		id:         id,
		aead:       aead,
		clientID:   clientID,
		clientAEAD: clientAEAD,
		last:       now,
	}
	c.sessions[clientID] = sess
	return sess, nil
}

type serverSession struct {
	cipher   *Cipher
	id       uint64
	aead     cipher.AEAD
	packetID atomic.Uint64

	clientID   uint64
	clientAEAD cipher.AEAD
	// last is guarded by Cipher.sessionMut.
	last time.Time

	mut    sync.Mutex
	window replayWindow
}

func (s *serverSession) accept(packetID uint64) bool {
	s.mut.Lock()
	defer s.mut.Unlock()
	if !s.window.valid(packetID) {
		return false
	}
	s.window.mark(packetID)
	return true
}

// Encrypt builds a response to the client of the session.
func (s *serverSession) Encrypt(dist, src []byte) (int, error) {
	var buf [1 + 8 + 8 + 2]byte
	meta := s.cipher.packetMeta(buf[:0], headerTypeServer, s.clientID)
	return s.cipher.sealPacket(dist, s.aead, s.id, s.packetID.Add(1)-1, meta, src)
}
