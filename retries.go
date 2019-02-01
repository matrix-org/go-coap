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
	// We store messages we put aside during handshakes here.
	// TODO: This will eventually need to be moved to a dedicated structure.
	hsQueue map[string][]HSQueueMsg
}

type queueEl struct {
	ch chan bool
	// We need to store sequence numbers in the queue in order to detect and
	// measure holes in the message queue, e.g. we'd need to re-handshake if we
	// observe a gap higher than 128 msgs (max(seqnum)/2).
	seqnum uint8
}

type HSQueueMsg struct {
	b           []byte  // We might do compression so we can't just call MarshalBinary
	m           Message // Kept for metadata access
	conn        *connUDP
	sessionData *SessionUDPData
}

func NewRetriesQueue() *RetriesQueue {
	rq := new(RetriesQueue)
	rq.q = make(map[uint16]queueEl)
	rq.mut = new(sync.Mutex)
	rq.hsQueue = make(map[string][]HSQueueMsg)
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
		if _, err := WriteToSessionUDP(conn, b, session); err != nil {
			debugf("Retried failed: %s", err.Error())
		}
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

func (rq *RetriesQueue) PushHS(msg HSQueueMsg) {
	if _, ok := rq.hsQueue[msg.sessionData.raddr.IP.String()]; !ok {
		rq.hsQueue[msg.sessionData.raddr.IP.String()] = make([]HSQueueMsg, 0)
	}
	rq.hsQueue[msg.sessionData.raddr.IP.String()] = append(rq.hsQueue[msg.sessionData.raddr.IP.String()], msg)
	return
}

func (rq *RetriesQueue) PopHS(host string) *HSQueueMsg {
	if q, ok := rq.hsQueue[host]; !ok || len(q) == 0 {
		return nil
	}

	bm := rq.hsQueue[host][0]

	if len(rq.hsQueue[host]) > 1 {
		rq.hsQueue[host] = rq.hsQueue[host][1:]
	} else {
		rq.hsQueue[host] = make([]HSQueueMsg, 0)
	}

	return &bm
}
