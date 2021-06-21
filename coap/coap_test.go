package coap

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/matrix-org/go-coap/v2/message"
	"github.com/matrix-org/go-coap/v2/message/codes"
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
	writes    map[string][][]byte
	onReceive func([]byte) []byte
}

func newCustomPacketConn(onReceive func([]byte) []byte) *customPacketConn {
	return &customPacketConn{
		writes:    make(map[string][][]byte),
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
	c.writes[addr.String()] = append(c.writes[addr.String()], p)
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
