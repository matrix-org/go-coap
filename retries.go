package coap

import (
	"net"
	"sync"
	"time"
)

type RetriesQueue struct {
	q      map[uint16]queueEl
	seqnum uint8 // Next sequence number, differs from the one in
	mut    *sync.Mutex
}

// We need to store sequence numbers in the queue in order to detect and measure
// holes in the message queue, e.g. we'd need to re-handshake if we observe a
// gap higher than 128 msgs (max(seqnum)/2).
type queueEl struct {
	ch     chan bool
	seqnum uint8
}

func NewRetriesQueue() *RetriesQueue {
	rq := new(RetriesQueue)
	rq.q = make(map[uint16]queueEl)
	rq.mut = new(sync.Mutex)
	return rq
}

func (rq *RetriesQueue) ScheduleRetry(mID uint16, timeToRetry time.Duration, b []byte, session *SessionUDPData, conn *net.UDPConn) {
	debugf("Scheduling retries for message %d", mID)

	rq.mut.Lock()

	ch := make(chan bool)
	if _, ok := rq.q[mID]; !ok {
		rq.q[mID] = queueEl{
			seqnum: rq.seqnum,
			ch:     ch,
		}
	}

	rq.mut.Unlock()

	select {
	case <-ch:
		// Cancel retry
		debugf("Received response for message %d, not retrying", mID)
		return
	case <-time.After(timeToRetry):
		// Wait a bit more then retry
		debugf("No response for message %d, retrying", mID)
		// if _, err := WriteToSessionUDP(conn.connection, b, session); err != nil {
		// 	debugf("Retried failed: %s", err.Error())
		// }
		rq.ScheduleRetry(mID, timeToRetry*2, b, session, conn)
	}
}

func (rq *RetriesQueue) CancelRetrySchedule(mID uint16) {
	rq.mut.Lock()

	if _, ok := rq.q[mID]; ok {
		debugf("Cancelling retry schedule for message %d", mID)

		rq.q[mID].ch <- true
		delete(rq.q, mID)
	}

	rq.mut.Unlock()
}
