package coap

import (
	"bytes"
	"log"
	"net"
	"sync/atomic"
	"time"
	// "runtime/debug"
)

type writeReq interface {
	sendResp(err error, timeout time.Duration)
	waitResp(timeout time.Duration) error
	data() Message
}

type writeReqBase struct {
	req      Message
	respChan chan error // channel must have size 1 for non-blocking write to channel
}

func (wreq *writeReqBase) sendResp(err error, timeout time.Duration) {
	select {
	case wreq.respChan <- err:
		return
	default:
		log.Fatal("Exactly one error can be send as resp. This is err.")
	}
}

func (wreq *writeReqBase) waitResp(timeout time.Duration) error {
	select {
	case err := <-wreq.respChan:
		return err
	case <-time.After(timeout):
		return ErrTimeout
	}
}

func (wreq *writeReqBase) data() Message {
	return wreq.req
}

type writeReqTCP struct {
	writeReqBase
}

type writeReqUDP struct {
	writeReqBase
	sessionData *SessionUDPData
	ns          *NoiseState
}

// Conn represents the connection
type Conn interface {
	// LocalAddr get local address of the connection
	LocalAddr() net.Addr
	// RemoteAddr get peer address of the connection
	RemoteAddr() net.Addr
	// Close close the connection
	Close() error

	write(w writeReq, timeout time.Duration) error
}

type connWriter interface {
	writeHandler(srv *Server) bool
	writeEndHandler(timeout time.Duration) bool
	sendFinish(timeout time.Duration)

	writeHandlerWithFunc(srv *Server, writeFunc func(srv *Server, wreq writeReq) error) bool
}

type connBase struct {
	writeChan chan writeReq
	closeChan chan bool
	finChan   chan bool
	closed    int32
	// ns        *NoiseState
}

func (conn *connBase) finishWrite() {
	if !atomic.CompareAndSwapInt32(&conn.closed, conn.closed, 1) {
		return
	}
	conn.closeChan <- true
	<-conn.finChan
}

func (conn *connBase) writeHandlerWithFunc(srv *Server, writeFunc func(srv *Server, wreq writeReq) error) bool {
	select {
	case wreq := <-conn.writeChan:
		wreq.sendResp(writeFunc(srv, wreq), srv.syncTimeout())
		return true
	case <-conn.closeChan:
		return false
	}
}

func (conn *connBase) sendFinish(timeout time.Duration) {
	select {
	case conn.finChan <- true:
	case <-time.After(timeout):
		log.Println("Client cannot recv start: Timeout")
	}
}

func (conn *connBase) writeEndHandler(timeout time.Duration) bool {
	select {
	case wreq := <-conn.writeChan:
		wreq.sendResp(ErrConnectionClosed, timeout)
		return true
	default:
		return false
	}
}

func (conn *connBase) write(w writeReq, timeout time.Duration) error {
	if atomic.LoadInt32(&conn.closed) > 0 {
		return ErrConnectionClosed
	}
	select {
	case conn.writeChan <- w:
		return w.waitResp(timeout)
	case <-time.After(timeout):
		return ErrTimeout
	}
}

type connTCP struct {
	connBase
	connection net.Conn // i/o connection if TCP was used
	num        int32
}

func (conn *connTCP) LocalAddr() net.Addr {
	return conn.connection.LocalAddr()
}

func (conn *connTCP) RemoteAddr() net.Addr {
	return conn.connection.RemoteAddr()
}

func (conn *connTCP) Close() error {
	conn.finishWrite()
	return conn.connection.Close()
}

func (conn *connTCP) writeHandler(srv *Server) bool {
	return conn.writeHandlerWithFunc(srv, func(srv *Server, wreq writeReq) error {
		data := wreq.data()
		wr := srv.acquireWriter(conn.connection)
		defer srv.releaseWriter(wr)
		writeTimeout := srv.writeTimeout()
		conn.connection.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := data.MarshalBinary(wr)
		if err != nil {
			return err
		}
		wr.Flush()
		return nil
	})
}

type connUDP struct {
	connBase
	connection *net.UDPConn // i/o connection if UDP was used
}

func (conn *connUDP) LocalAddr() net.Addr {
	return conn.connection.LocalAddr()
}

func (conn *connUDP) RemoteAddr() net.Addr {
	return conn.connection.RemoteAddr()
}

func (conn *connUDP) SetReadDeadline(timeout time.Time) error {
	return conn.connection.SetReadDeadline(timeout)
}

func (conn *connUDP) ReadFromSessionUDP(m []byte) (int, *SessionUDPData, error) {
	return ReadFromSessionUDP(conn.connection, m)
}

func (conn *connUDP) Close() error {
	conn.finishWrite()
	return conn.connection.Close()
}

func (conn *connUDP) writeHandler(srv *Server) bool {
	return conn.writeHandlerWithFunc(srv, func(srv *Server, wreq writeReq) error {
		data := wreq.data()
		wreqUDP := wreq.(*writeReqUDP)
		writeTimeout := srv.writeTimeout()
		buf := &bytes.Buffer{}
		err := data.MarshalBinary(buf)
		if err != nil {
			return err
		}

		// TODO:
		//
		// before compressing, we have to move the coap headers to the cleartext payload
		// we move:
		//
		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |Ver| T |  TKL  |      Code     |          Message ID           |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |   Token (if any, TKL bytes) ...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// We leave the options and subsequent CBOR payloads however encrypted.

		// We calculate an 8-bit sequence number at this point from the noise
		// handshake state's nonce, and append it to the headers - we need
		// this to do reordering on receipt to hand the
		// packets to noise in the write order and without dups or gaps.

		// We package up our XX and IK noise handshakes with the same headers
		// as if they were CoAP.  No token is needed.  We'll need to pick a
		// custom CoAP code.  Suggestion:

		// Handshake | CoAP Type | CoAP Code |
		// ----------|-----------|-----------|
		// XX1       | 0         | 250       |
		// XX2       | 2         | 250       |
		// XX3       | 1         | 251       |
		// IK1       | 0         | 252       |
		// IK2       | 2         | 252       |

		// We could be naughty and set Ver=011b rather than 001b to indicate
		// that encryption is turned on, in order to negotiate it more elegantly

		var compressed []byte
		if srv.Compressor != nil {
			compressed, err = srv.Compressor.CompressPayload(buf.Bytes())
			if err != nil {
				return err
			}
			//log.Printf("Compressed packet: %d -> %d bytes", len(buf.Bytes()), len(compressed))
		} else {
			compressed = buf.Bytes()
		}

		conn.connection.SetWriteDeadline(time.Now().Add(writeTimeout))

		var msg []byte
		if srv.Encryption {
			ns := wreqUDP.ns
			// log.Printf("encrypting %d bytes with %+v as %v", len(compressed), ns, compressed)
			err = ns.EncryptAndSendMessage(compressed, conn.connection, wreqUDP.sessionData)
			if err != nil {
				log.Printf("failed to encrypt message: %v", err)
				return err
			}
		} else {
			msg = compressed
			_, err = WriteToSessionUDP(conn.connection, msg, wreqUDP.sessionData)
			return err
		}

		// TODO:
		// Rather than having noise send directly or handle retries itself, noise needs to pass
		// back the payload and we then retry (re)sending it here, as a bunch of bits.
		//
		// We need to track the msgid+token pair of the confirmable messages being sent, so we know when to
		// keep retrying.  (As when we receive the ID of the response, we should stop retrying.)
	})
}

func newConnectionTCP(c net.Conn, srv *Server) Conn {
	connection := &connTCP{connBase: connBase{writeChan: make(chan writeReq, 10000), closeChan: make(chan bool), finChan: make(chan bool), closed: 0}, connection: c}
	go writeToConnection(connection, srv)
	return connection
}

func newConnectionUDP(c *net.UDPConn, srv *Server) Conn {

	connection := &connUDP{connBase: connBase{writeChan: make(chan writeReq, 10000), closeChan: make(chan bool), finChan: make(chan bool), closed: 0}, connection: c}

	//log.Printf("newConnectionUDP called with conn=%p", connection)
	//debug.PrintStack()

	go writeToConnection(connection, srv)
	return connection
}

func writeToConnection(conn connWriter, srv *Server) {
	for conn.writeHandler(srv) {
	}
	for conn.writeEndHandler(srv.syncTimeout()) {
	}
	conn.sendFinish(srv.syncTimeout())
}
