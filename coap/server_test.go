package coap

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/matrix-org/go-coap/v2/message"
	"github.com/matrix-org/go-coap/v2/message/codes"
	"github.com/matrix-org/go-coap/v2/udp/client"
	"github.com/matrix-org/go-coap/v2/udp/message/pool"
)

type packet struct {
	raddr net.Addr
	data  []byte
}

type multiplexPacketConn struct {
	laddr  net.Addr
	reads  chan packet
	writes chan packet
}

// ReadFrom reads a packet from the connection,
// copying the payload into p. It returns the number of
// bytes copied into p and the return address that
// was on the packet.
// It returns the number of bytes read (0 <= n <= len(p))
// and any error encountered. Callers should always process
// the n > 0 bytes returned before considering the error err.
// ReadFrom can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetReadDeadline.
func (c *multiplexPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for data := range c.reads {
		n = copy(p, data.data)
		return n, data.raddr, nil
	}
	return 0, nil, fmt.Errorf("read on closed chan: %+v", c.reads)
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *multiplexPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	pCopy := make([]byte, len(p))
	copy(pCopy, p)
	c.writes <- packet{
		data:  pCopy,
		raddr: addr,
	}
	return len(p), nil
}
func (c *multiplexPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *multiplexPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *multiplexPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *multiplexPacketConn) Close() error {
	close(c.reads)
	close(c.writes)
	return nil
}
func (c *multiplexPacketConn) LocalAddr() net.Addr {
	return c.laddr
}

// Test that the server config can serve multiple clients with the same pconn without getting confused.
func TestCoapServer(t *testing.T) {
	pconn := &multiplexPacketConn{
		laddr:  &customAddr{network: "test", str: "SERVER"},
		reads:  make(chan packet),
		writes: make(chan packet),
	}
	addrA := &customAddr{network: "test", str: "A"}
	addrB := &customAddr{network: "test", str: "B"}
	addrC := &customAddr{network: "test", str: "C"}

	// Server echos back the remote address
	serverCfg := NewConfig(WithErrors(func(err error) {
		t.Fatalf("CoAP error: %s", err)
	}), WithHandlerFunc(func(rw *client.ResponseWriter, m *pool.Message) {
		addrStr := rw.ClientConn().RemoteAddr().String()
		rw.SetResponse(codes.Content, message.TextPlain, bytes.NewReader([]byte(addrStr)))
	}))
	srv := serverCfg.NewServer(pconn)
	defer srv.Close()

	go func() {
		err := srv.Serve()
		if err != nil {
			t.Errorf("Serve returned: %s", err)
		}
	}()
	time.Sleep(10 * time.Millisecond) // yuck

	testAddrs := []net.Addr{
		addrA, addrB, addrC, addrA, addrA, addrB,
	}
	for _, testAddr := range testAddrs {
		t.Logf("Testing with %s", testAddr)
		msg, err := client.NewGetRequest(context.Background(), "/")
		if err != nil {
			t.Fatalf("Failed to NewGetRequest: %s", err)
		}
		coapGetDataBytes, err := msg.Marshal()
		if err != nil {
			t.Fatalf("Failed to Marshal GET request: %s", err)
		}

		pconn.reads <- packet{
			raddr: testAddr,
			data:  coapGetDataBytes,
		}
		select {
		case pkt := <-pconn.writes:
			if pkt.raddr.String() != testAddr.String() {
				t.Errorf("response contains wrong raddr, got %s want %s", pkt.raddr.String(), testAddr.String())
			}
			recvMsg := pool.AcquireMessage(context.Background())
			t.Logf("recv %x", pkt.data)
			_, err = recvMsg.Unmarshal(pkt.data)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %s", err)
			}
			body, err := ioutil.ReadAll(recvMsg.Body())
			if err != nil {
				t.Fatalf("Failed to read response body: %s", err)
			}
			if string(body) != testAddr.String() {
				t.Errorf("response body contained wrong addr, got %s want %s", string(body), testAddr.String())
			}
			if recvMsg.MessageID() != msg.MessageID() {
				t.Errorf("response has wrong MID, got %d want %d", recvMsg.MessageID(), msg.MessageID())
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("response was not written")
		}
	}
}
