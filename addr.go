package shadowsocks

import "github.com/wzshiming/shadowsocks/internal/socks"

// Addr is the target of a connection or a packet.
// Either Name or IP is used exclusively.
type Addr = socks.Addr
