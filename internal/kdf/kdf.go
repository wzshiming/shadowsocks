// Package kdf derives keys from passwords.
package kdf

import "crypto/md5"

// KDF is the key-derivation function of the original Shadowsocks.
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
