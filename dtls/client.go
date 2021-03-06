package dtls

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/matrix-org/go-coap/v2/message"
	"github.com/matrix-org/go-coap/v2/net/blockwise"
	"github.com/matrix-org/go-coap/v2/net/monitor/inactivity"
	"github.com/matrix-org/go-coap/v2/shared"
	"github.com/pion/dtls/v2"

	"github.com/matrix-org/go-coap/v2/message/codes"
	coapNet "github.com/matrix-org/go-coap/v2/net"
	"github.com/matrix-org/go-coap/v2/udp/client"
	udpMessage "github.com/matrix-org/go-coap/v2/udp/message"
	"github.com/matrix-org/go-coap/v2/udp/message/pool"
	kitSync "github.com/plgd-dev/kit/sync"
)

var defaultDialOptions = dialOptions{
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
	dialer:                         &net.Dialer{Timeout: time.Second * 3},
	net:                            "udp",
	blockwiseSZX:                   blockwise.SZX1024,
	blockwiseEnable:                true,
	blockwiseTransferTimeout:       time.Second * 5,
	transmissionNStart:             time.Second,
	transmissionAcknowledgeTimeout: time.Second * 2,
	transmissionMaxRetransmit:      4,
	getMID:                         udpMessage.GetMID,
	createInactivityMonitor: func() inactivity.Monitor {
		return inactivity.NewNilMonitor()
	},
}

type dialOptions struct {
	ctx                            context.Context
	maxMessageSize                 int
	heartBeat                      time.Duration
	handler                        HandlerFunc
	errors                         ErrorFunc
	goPool                         GoPoolFunc
	dialer                         *net.Dialer
	net                            string
	blockwiseSZX                   blockwise.SZX
	blockwiseEnable                bool
	blockwiseTransferTimeout       time.Duration
	transmissionNStart             time.Duration
	transmissionAcknowledgeTimeout time.Duration
	transmissionMaxRetransmit      int
	getMID                         GetMIDFunc
	closeSocket                    bool
	createInactivityMonitor        func() inactivity.Monitor
	logger                         shared.Logger
}

// A DialOption sets options such as credentials, keepalive parameters, etc.
type DialOption interface {
	applyDial(*dialOptions)
}

// Dial creates a client connection to the given target.
func Dial(target string, dtlsCfg *dtls.Config, opts ...DialOption) (*client.ClientConn, error) {
	cfg := defaultDialOptions
	for _, o := range opts {
		o.applyDial(&cfg)
	}

	c, err := cfg.dialer.DialContext(cfg.ctx, cfg.net, target)
	if err != nil {
		return nil, err
	}

	conn, err := dtls.Client(c, dtlsCfg)
	if err != nil {
		return nil, err
	}
	opts = append(opts, WithCloseSocket())
	return Client(conn, opts...), nil
}

func bwAcquireMessage(ctx context.Context) blockwise.Message {
	msg := pool.AcquireMessage(ctx)
	msg.SetType(udpMessage.Confirmable)
	return msg
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

// Client creates client over dtls connection.
func Client(conn *dtls.Conn, opts ...DialOption) *client.ClientConn {
	cfg := defaultDialOptions
	for _, o := range opts {
		o.applyDial(&cfg)
	}
	if cfg.errors == nil {
		cfg.errors = func(error) {}
	}
	if cfg.createInactivityMonitor == nil {
		cfg.createInactivityMonitor = func() inactivity.Monitor {
			return inactivity.NewNilMonitor()
		}
	}
	errors := cfg.errors
	cfg.errors = func(err error) {
		errors(fmt.Errorf("dtls: %v: %w", conn.RemoteAddr(), err))
	}

	observatioRequests := kitSync.NewMap()
	var blockWise *blockwise.BlockWise
	if cfg.blockwiseEnable {
		blockWise = blockwise.NewBlockWise(
			bwAcquireMessage,
			bwReleaseMessage,
			cfg.blockwiseTransferTimeout,
			cfg.errors,
			false,
			bwCreateHandlerFunc(observatioRequests),
			cfg.logger,
		)
	}

	observationTokenHandler := client.NewHandlerContainer()
	monitor := cfg.createInactivityMonitor()
	var cc *client.ClientConn
	l := coapNet.NewConn(conn, coapNet.WithHeartBeat(cfg.heartBeat), coapNet.WithOnReadTimeout(func() error {
		monitor.CheckInactivity(cc)
		return nil
	}))
	session := NewSession(cfg.ctx,
		l,
		cfg.maxMessageSize,
		cfg.closeSocket,
	)
	cc = client.NewClientConn(session,
		observationTokenHandler, observatioRequests, cfg.transmissionNStart, cfg.transmissionAcknowledgeTimeout, cfg.transmissionMaxRetransmit,
		client.NewObservationHandler(observationTokenHandler, cfg.handler),
		cfg.blockwiseSZX,
		blockWise,
		cfg.goPool,
		cfg.errors,
		cfg.getMID,
		// The client does not support activity monitoring yet
		monitor,
		cfg.logger,
	)

	go func() {
		err := cc.Run()
		if err != nil {
			cfg.errors(err)
		}
	}()

	return cc
}
