# Go-CoAP

This is the matrix.org fork of go-coap, specialised for [MSC3079](https://github.com/matrix-org/matrix-doc/pull/3079).
There are several reasons to fork [the original implementation](https://github.com/plgd-dev/go-coap):
 - FIN packet handling is easier to do at the go-coap level, and is matrix.org specific.
   See [these comments](https://github.com/matrix-org/matrix-doc/blob/kegan/low-bandwidth/proposals/3079-low-bandwidth-csapi.md#potential-issues) for context.
 - We were hitting many known issues with the original implementation around retry handling, congestion control (NSTART handling),
   accessing MIDs on UDP messages, etc.
 - We want to add WebSockets support.

This repo was originally forked from an even earlier implementation for
[FOSDEM 2019](https://matrix.org/blog/2019/03/12/breaking-the-100-bps-barrier-with-matrix-meshsim-coap-proxy), but this new
work is based on [v2.4.0](https://github.com/plgd-dev/go-coap/releases/tag/v2.4.0).

The go-coap provides servers and clients for DTLS, TCP-TLS, UDP, TCP in golang.

## Features
* CoAP over UDP [RFC 7252][coap].
* CoAP over TCP/TLS [RFC 8232][coap-tcp]
* Observe resources in CoAP [RFC 7641][coap-observe]
* Block-wise transfers in CoAP [RFC 7959][coap-block-wise-transfers]
* request multiplexer
* multicast
* CoAP NoResponse option in CoAP [RFC 7967][coap-noresponse]
* CoAP over DTLS [pion/dtls][pion-dtls]

[coap]: http://tools.ietf.org/html/rfc7252
[coap-tcp]: https://tools.ietf.org/html/rfc8323
[coap-block-wise-transfers]: https://tools.ietf.org/html/rfc7959
[coap-observe]: https://tools.ietf.org/html/rfc7641
[coap-noresponse]: https://tools.ietf.org/html/rfc7967
[pion-dtls]: https://github.com/pion/dtls

## Samples

### Simple

#### Server UDP/TCP
```go
	// Server
	
	// Middleware function, which will be called for each request.
	func loggingMiddleware(next mux.Handler) mux.Handler {
		return mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
			log.Printf("ClientAddress %v, %v\n", w.Client().RemoteAddr(), r.String())
			next.ServeCOAP(w, r)
		})
	}
	
	// See /examples/simple/server/main.go
	func handleA(w mux.ResponseWriter, req *mux.Message) {
		err := w.SetResponse(codes.GET, message.TextPlain, bytes.NewReader([]byte("hello world")))
		if err != nil {
			log.Printf("cannot set response: %v", err)
		}
	}

	func main() {
		r := mux.NewRouter()
		r.Use(loggingMiddleware)
		r.Handle("/a", mux.HandlerFunc(handleA))
		r.Handle("/b", mux.HandlerFunc(handleB))

		log.Fatal(coap.ListenAndServe("udp", ":5688", r))

		
		// for tcp
		// log.Fatal(coap.ListenAndServe("tcp", ":5688",  r))

		// for tcp-tls
		// log.Fatal(coap.ListenAndServeTLS("tcp", ":5688", &tls.Config{...}, r))

		// for udp-dtls
		// log.Fatal(coap.ListenAndServeDTLS("udp", ":5688", &dtls.Config{...}, r))
	}
```
#### Client
```go
	// Client
	// See /examples/simpler/client/main.go
	func main() {
		co, err := udp.Dial("localhost:5688")
		
		// for tcp
		// co, err := tcp.Dial("localhost:5688")
		
		// for tcp-tls
		// co, err := tcp.Dial("localhost:5688", tcp.WithTLS(&tls.Config{...}))

		// for dtls
		// co, err := dtls.Dial("localhost:5688", &dtls.Config{...}))

		if err != nil {
			log.Fatalf("Error dialing: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := co.Get(ctx, "/a")
		if err != nil {
			log.Fatalf("Cannot get response: %v", err)
			return
		}
		log.Printf("Response: %+v", resp)
	}
```

### Observe / Notify

[Server](examples/observe/server/main.go) example.

[Client](examples/observe/client/main.go) example.

### Multicast

[Server](examples/mcast/server/main.go) example.

[Client](examples/mcast/client/main.go) example.

## Contributing

In order to run the tests that the CI will run locally, the following two commands can be used to build the Docker image and run the tests. When making changes, these are the tests that the CI will run, so please make sure that the tests work locally before committing.

```shell
$ docker build . --network=host -t go-coap:build --target build
$ docker run --mount type=bind,source="$(pwd)",target=/shared,readonly --network=host go-coap:build go test './...'
```