package coap

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/matrix-org/go-coap/v2/message"
	"github.com/matrix-org/go-coap/v2/message/codes"
	"github.com/matrix-org/go-coap/v2/net/blockwise"
	"github.com/matrix-org/go-coap/v2/net/monitor/inactivity"
	"github.com/matrix-org/go-coap/v2/shared"
	"github.com/matrix-org/go-coap/v2/udp/client"
	"github.com/matrix-org/go-coap/v2/udp/message/pool"
	kitSync "github.com/plgd-dev/kit/sync"
)

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as COAP handlers.
type HandlerFunc = func(*client.ResponseWriter, *pool.Message)

type ConfigOpt func(c *Config)

type Config struct {
	ctx                            context.Context
	maxMessageSize                 int
	heartBeat                      time.Duration
	handler                        HandlerFunc
	errors                         func(error)
	goPool                         func(func()) error
	blockwiseSZX                   blockwise.SZX
	blockwiseEnable                bool
	blockwiseTransferTimeout       time.Duration
	transmissionNStart             time.Duration
	transmissionAcknowledgeTimeout time.Duration
	transmissionMaxRetransmit      int
	getMID                         func() uint16
	closeSocket                    bool
	createInactivityMonitor        func() inactivity.Monitor
	onNewClientConn                func(cc *client.ClientConn)
	logger                         shared.Logger
}

func bwAcquireMessage(ctx context.Context) blockwise.Message {
	return pool.AcquireMessage(ctx)
}

func bwReleaseMessage(m blockwise.Message) {
	pool.ReleaseMessage(m.(*pool.Message))
}

func bwCreateHandlerFunc(observatioRequests *kitSync.Map) func(token message.Token) (blockwise.Message, bool) {
	return func(token message.Token) (blockwise.Message, bool) {
		msg, ok := observatioRequests.LoadWithFunc(token.String(), func(v interface{}) interface{} {
			r := v.(*pool.Message)
			d := pool.AcquireMessage(r.Context())
			d.ResetOptionsTo(r.Options())
			d.SetCode(r.Code())
			d.SetToken(r.Token())
			d.SetMessageID(r.MessageID())
			return d
		})
		if !ok {
			return nil, ok
		}
		bwMessage := msg.(blockwise.Message)
		return bwMessage, ok
	}
}

func (c *Config) NewServer(pconn net.PacketConn) *Server {
	return &Server{
		cfg:             c,
		pconn:           pconn,
		connsMu:         &sync.Mutex{},
		conns:           make(map[string]*client.ClientConn),
		onNewClientConn: c.onNewClientConn,
	}
}

func (c *Config) NewSessionWithPacketConn(pconn net.PacketConn, raddr net.Addr) *client.ClientConn {
	return c.NewWithSession(NewSession(
		context.Background(), pconn, raddr, c.maxMessageSize, c.closeSocket,
	))
}

func (c *Config) NewWithSession(session client.Session) *client.ClientConn {
	observationTokenHandler := client.NewHandlerContainer()
	observatioRequests := kitSync.NewMap()

	var blockWise *blockwise.BlockWise
	if c.blockwiseEnable {
		blockWise = blockwise.NewBlockWise(
			bwAcquireMessage,
			bwReleaseMessage,
			c.blockwiseTransferTimeout,
			c.errors,
			false,
			bwCreateHandlerFunc(observatioRequests),
			c.logger,
		)
	}
	return client.NewClientConn(
		session, observationTokenHandler, observatioRequests,
		c.transmissionNStart, c.transmissionAcknowledgeTimeout, c.transmissionMaxRetransmit,
		c.handler, c.blockwiseSZX, blockWise, c.goPool, c.errors, c.getMID, c.createInactivityMonitor(), c.logger,
	)
}

var defaultConfigOpts = Config{
	ctx:            context.Background(),
	maxMessageSize: 64 * 1024,
	heartBeat:      time.Millisecond * 100,
	handler: func(w *client.ResponseWriter, r *pool.Message) {
		switch r.Code() {
		case codes.POST, codes.PUT, codes.GET, codes.DELETE:
			w.SetResponse(codes.NotFound, message.TextPlain, nil)
		}
	},
	errors: func(err error) {
		fmt.Println(err)
	},
	goPool: func(f func()) error {
		go func() {
			f()
		}()
		return nil
	},
	blockwiseSZX:                   blockwise.SZX1024,
	blockwiseEnable:                true,
	blockwiseTransferTimeout:       time.Second * 5,
	transmissionNStart:             time.Second,
	transmissionAcknowledgeTimeout: time.Second * 2,
	transmissionMaxRetransmit:      4,
	getMID:                         GetMID,
	createInactivityMonitor: func() inactivity.Monitor {
		return inactivity.NewNilMonitor()
	},
}

func NewConfig(opts ...ConfigOpt) *Config {
	cfg := defaultConfigOpts
	for _, opt := range opts {
		opt(&cfg)
	}
	return &cfg
}

func WithHandlerFunc(h HandlerFunc) ConfigOpt {
	return func(c *Config) {
		c.handler = h
	}
}

func WithContext(ctx context.Context) ConfigOpt {
	return func(c *Config) {
		c.ctx = ctx
	}
}

func WithMaxMessageSize(maxMessageSize int) ConfigOpt {
	return func(c *Config) {
		c.maxMessageSize = maxMessageSize
	}
}

func WithErrors(errors func(error)) ConfigOpt {
	return func(c *Config) {
		c.errors = errors
	}
}

// WithGoPool sets function for managing spawning go routines
// for handling incoming request's.
// Eg: https://github.com/panjf2000/ants.
func WithGoPool(goPool func(func()) error) ConfigOpt {
	return func(c *Config) {
		c.goPool = goPool
	}
}

func WithOnNewClientConn(fn func(cc *client.ClientConn)) ConfigOpt {
	return func(c *Config) {
		c.onNewClientConn = fn
	}
}

func WithKeepAlive(maxRetries uint32, timeout time.Duration, onInactive inactivity.OnInactiveFunc) ConfigOpt {
	return func(c *Config) {
		c.createInactivityMonitor = func() inactivity.Monitor {
			keepalive := inactivity.NewKeepAlive(maxRetries, onInactive, func(cc inactivity.ClientConn, receivePong func()) (func(), error) {
				return cc.(*client.ClientConn).AsyncPing(receivePong)
			})
			return inactivity.NewInactivityMonitor(timeout/time.Duration(maxRetries+1), keepalive.OnInactive)
		}
	}
}

func WithInactivityMonitor(duration time.Duration, onInactive inactivity.OnInactiveFunc) ConfigOpt {
	return func(c *Config) {
		c.createInactivityMonitor = func() inactivity.Monitor {
			return inactivity.NewInactivityMonitor(duration, onInactive)
		}
	}
}

// WithHeartBeat set deadline's for read/write operations over client connection.
func WithHeartBeat(heartbeat time.Duration) ConfigOpt {
	return func(c *Config) {
		c.heartBeat = heartbeat
	}
}

func WithBlockwise(enable bool, szx blockwise.SZX, transferTimeout time.Duration) ConfigOpt {
	return func(c *Config) {
		c.blockwiseEnable = enable
		c.blockwiseSZX = szx
		c.blockwiseTransferTimeout = transferTimeout
	}
}

// WithTransmission set options for (re)transmission for Confirmable message-s.
func WithTransmission(transmissionNStart time.Duration,
	transmissionAcknowledgeTimeout time.Duration,
	transmissionMaxRetransmit int) ConfigOpt {
	return func(c *Config) {
		c.transmissionNStart = transmissionNStart
		c.transmissionAcknowledgeTimeout = transmissionAcknowledgeTimeout
		c.transmissionMaxRetransmit = transmissionMaxRetransmit
	}
}

// WithGetMID allows to set own getMID function to server/client.
func WithGetMID(getMID func() uint16) ConfigOpt {
	return func(c *Config) {
		c.getMID = getMID
	}
}

// WithCloseSocket closes socket at the close connection.
func WithCloseSocket() ConfigOpt {
	return func(c *Config) {
		c.closeSocket = true
	}
}

// WithLogger adds logging
func WithLogger(logger shared.Logger) ConfigOpt {
	return func(c *Config) {
		c.logger = logger
	}
}
