package coap

import (
	"fmt"
	"net"
	"sync"

	"github.com/matrix-org/go-coap/v2/udp/client"
)

type Server struct {
	cfg             *Config
	pconn           net.PacketConn
	connsMu         *sync.Mutex
	conns           map[string]*client.ClientConn
	onNewClientConn func(cc *client.ClientConn)
}

func (s *Server) Serve() error {
	m := make([]byte, s.cfg.maxMessageSize)

	for {
		buf := m
		n, raddr, err := s.pconn.ReadFrom(buf)
		if err != nil {
			return err
		}
		buf = buf[:n]
		cc, created := s.getOrCreateClientConn(raddr)
		if created {
			if s.onNewClientConn != nil {
				s.onNewClientConn(cc)
			}
		}
		err = cc.Process(buf)
		if err != nil {
			cc.Close()
			s.cfg.errors(fmt.Errorf("%v: %w", cc.RemoteAddr(), err))
		}
	}
}

// Close stops server without wait of ends Serve function.
func (s *Server) Close() {
	s.closeSessions()
}

func (s *Server) closeSessions() {
	s.connsMu.Lock()
	conns := s.conns
	s.conns = make(map[string]*client.ClientConn)
	s.connsMu.Unlock()
	for _, cc := range conns {
		cc.Close()
	}
}

func (s *Server) getOrCreateClientConn(raddr net.Addr) (cc *client.ClientConn, created bool) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	key := raddr.String()
	cc = s.conns[key]
	if cc != nil {
		return cc, false
	}
	// don't call cc.Run() as we are already consuming from conn
	cc = s.cfg.NewSessionWithPacketConn(s.pconn, raddr)
	s.conns[key] = cc
	return cc, true
}
