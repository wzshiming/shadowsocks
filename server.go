package shadowsocks

import (
	"context"
	"net"
)

// Server is accepting connections and handling the details of the shadowsocks protocol
type Server struct {
	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
	// Logger error log
	Logger Logger
	// Context is default context
	Context context.Context
	// Cipher use cipher protocol
	Cipher string
	// Password use password authentication
	Password string
	// ConnCipher is connect the cipher codec
	ConnCipher ConnCipher
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool BytesPool
}

// NewServer creates a new Server
func NewServer() *Server {
	return &Server{}
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	var lc net.ListenConfig
	l, err := lc.Listen(s.context(), network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	err := s.serveConn(conn)
	if err != nil && s.Logger != nil && !isClosedConnError(err) {
		s.Logger.Println(err)
	}
}

func (s *Server) serveConn(conn net.Conn) error {
	ctx := s.context()
	conn = s.ConnCipher.StreamConn(conn)
	addr, err := readAddress(conn)
	if err != nil {
		return err
	}
	c, err := s.proxyDial(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
	}
	return tunnel(ctx, c, conn, buf1, buf2)
}

func (s *Server) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := s.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}

func (s *Server) context() context.Context {
	if s.Context == nil {
		return context.Background()
	}
	return s.Context
}
