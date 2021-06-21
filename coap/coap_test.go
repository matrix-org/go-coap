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
	udpMessage "github.com/matrix-org/go-coap/v2/udp/message"
	"github.com/matrix-org/go-coap/v2/udp/message/pool"
)

type customAddr struct {
	network string
	str     string
}

func (a *customAddr) Network() string {
	return a.network
}
func (a *customAddr) String() string {
	return a.str
}

type customPacketConn struct {
	closed    bool
	reads     chan []byte
	onReceive func([]byte) []byte
}

func newCustomPacketConn(onReceive func([]byte) []byte) *customPacketConn {
	return &customPacketConn{
		reads:     make(chan []byte),
		onReceive: onReceive,
	}
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
func (c *customPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for data := range c.reads {
		n = copy(p, data)
		return n, &customAddr{"custom", "read-from-addr"}, nil
	}
	return 0, nil, fmt.Errorf("read on closed chan: %+v", c.reads)
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *customPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	output := c.onReceive(p)
	if output != nil {
		c.reads <- output
	}
	return 0, nil
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (c *customPacketConn) Close() error {
	c.closed = true
	return nil
}

// LocalAddr returns the local network address.
func (c *customPacketConn) LocalAddr() net.Addr {
	return &customAddr{"custom", "local-addr"}
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to ReadFrom or
// WriteTo. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful ReadFrom or WriteTo calls.
//
// A zero value for t means I/O operations will not time out.
func (c *customPacketConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (c *customPacketConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (c *customPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// Tests that you can send CoAP pings to a target using an arbitrary net.PacketConn
func TestCoapPing(t *testing.T) {
	cfg := NewConfig(WithErrors(func(err error) {
		t.Fatalf("CoAP error: %s", err)
	}))
	raddr := &customAddr{"custom", "0502030493252"}
	pconn := newCustomPacketConn(func(b []byte) []byte {
		fmt.Printf("onReceive: %x\n", b)
		input := pool.AcquireMessage(context.Background())
		_, err := input.Unmarshal(b)
		if err != nil {
			t.Fatalf("failed to unmarshal msg: %s", err)
		}

		msg := pool.AcquireMessage(context.Background())
		msg.SetCode(codes.Empty)
		msg.SetContentFormat(message.TextPlain)
		msg.SetMessageID(input.MessageID())
		msg.SetType(udpMessage.Acknowledgement)
		output, err := msg.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal output msg: %s", err)
		}
		fmt.Printf("responding %x\n", output)
		return output
	})
	conn := cfg.NewWithPacketConn(pconn, raddr)
	go func() {
		err := conn.Run()
		if err != nil {
			t.Errorf("Failed to listen on packet conn: %s", err)
		}
	}()
	err := conn.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping failed: %s", err)
	}
}

// channelPacketConn is a net.PacketConn using channels. It can only talk to one remote addr marked
// by 'raddr'.
type channelPacketConn struct {
	reads  chan []byte
	writes chan []byte
	laddr  net.Addr
	raddr  net.Addr
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
func (c *channelPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for data := range c.reads {
		n = copy(p, data)
		return n, c.raddr, nil
	}
	return 0, nil, fmt.Errorf("read on closed chan: %+v", c.reads)
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *channelPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr.String() != c.raddr.String() {
		return 0, fmt.Errorf("unexpected raddr: got %s want %s", addr.String(), c.raddr.String())
	}
	c.writes <- p
	return len(p), nil
}
func (c *channelPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *channelPacketConn) Close() error {
	close(c.reads)
	close(c.writes)
	return nil
}
func (c *channelPacketConn) LocalAddr() net.Addr {
	return c.laddr
}

// Test that blockwise xfer works between a client/server using a custom net.PacketConn as the transport
func TestCoapBlockwiseClientServer(t *testing.T) {
	bigPayload := make([]byte, 1024*1024*2) // 2MB
	for i := range bigPayload {
		bigPayload[i] = byte(i % 256)
	}
	clientToServerCh := make(chan []byte, 10)
	serverToClientCh := make(chan []byte, 10)
	clientAddr := customAddr{"coap", "client"}
	serverAddr := customAddr{"coap", "server"}

	clientToServerPipe := &channelPacketConn{
		reads:  serverToClientCh,
		writes: clientToServerCh,
		laddr:  &clientAddr,
		raddr:  &serverAddr,
	}
	serverToClientPipe := &channelPacketConn{
		reads:  clientToServerCh,
		writes: serverToClientCh,
		laddr:  &serverAddr,
		raddr:  &clientAddr,
	}

	// blockwise xfer is enabled by default
	clientCfg := NewConfig(WithErrors(func(err error) {
		t.Fatalf("CoAP error: %s", err)
	}))
	serverCfg := NewConfig(WithErrors(func(err error) {
		t.Fatalf("CoAP error: %s", err)
	}), WithHandlerFunc(func(rw *client.ResponseWriter, m *pool.Message) {
		path, _ := m.Options().Path()
		fmt.Println(path)
		if path == "give/me/data" {
			rw.SetResponse(codes.Content, message.TextPlain, bytes.NewReader(bigPayload))
		}
	}))

	clientsConn := clientCfg.NewWithPacketConn(clientToServerPipe, &serverAddr)
	serversConn := serverCfg.NewWithPacketConn(serverToClientPipe, &clientAddr)

	go func() {
		if err := clientsConn.Run(); err != nil {
			t.Errorf("failed to run client conn: %s", err)
		}
	}()
	go func() {
		if err := serversConn.Run(); err != nil {
			t.Errorf("failed to run server conn: %s", err)
		}
	}()

	// Do pings to make sure the pipes are configured correctly
	err := clientsConn.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping from client to server failed: %s", err)
	}
	err = serversConn.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping from server to client failed: %s", err)
	}

	// ask the server for the big payload
	resp, err := clientsConn.Get(context.Background(), "/give/me/data")
	if err != nil {
		t.Fatalf("clientsConn.Get failed: %s", err)
	}
	gotPayload, err := ioutil.ReadAll(resp.Body())
	if err != nil {
		t.Fatalf("Failed to read response body: %s", err)
	}
	if !bytes.Equal(bigPayload, gotPayload) {
		t.Fatalf("Payload received mismatch, got %d bytes, want %d bytes", len(gotPayload), len(bigPayload))
	}

}
