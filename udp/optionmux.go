package udp

import (
	"github.com/matrix-org/go-coap/v2/mux"
	"github.com/matrix-org/go-coap/v2/udp/client"
)

// WithMux set's multiplexer for handle requests.
func WithMux(m mux.Handler) HandlerFuncOpt {
	return WithHandlerFunc(client.HandlerFuncToMux(m))
}
