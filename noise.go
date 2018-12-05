package coap

import (
	"crypto/rand"
	"errors"
	"github.com/flynn/noise"
	"io"
	"log"
	"net"
)

type NoisePipeState int

const (
	START NoisePipeState = 0 // our starting point

	// if we have no static key for our peer:
	XX1 NoisePipeState = 1 // -> e
	XX2 NoisePipeState = 2 // <- e, ee, s, es + payload  (initiator stores s as peer). Payload is empty given the receiver has nothing yet to say.
	XX3 NoisePipeState = 3 // -> s, se        + payload  (receiver stores for that peer). Payload is the CoAP req from the initiator.

	// and then we're established.
	READY NoisePipeState = 4 // send & encrypt via respective CipherStates

	// else, if we have a static key for our peer:
	IK1 NoisePipeState = 5 // -> e, es, s, ss + payload  (payload is CoAP req)

	// after receiving an IK1 we try to decrypt, and if decryption fails we assume the
	// initiatior is instead trying to talk XX to us and so we treat it as an XX1 and
	// switch to XXfallback instead.

	IK2 NoisePipeState = 6 // <- e, ee, se    + payload  (payload is CoAP ack)

	// and then we're established again.

	// If something goes wrong...
	ERROR NoisePipeState = 7
)

type KeyStore interface {
	GetLocalKey() (*noise.DHKey, error)
	SetLocalKey(*noise.DHKey) error

	GetRemoteKey(net.Addr) ([]byte, error)
	SetRemoteKey(net.Addr, []byte) error
}

type NoiseState struct {
	Hs              *noise.HandshakeState
	Cs              *noise.CipherSuite
	Rng             io.Reader
	PipeState       NoisePipeState
	connection      Conn
	keyStore        KeyStore
	LocalStaticKey  noise.DHKey
	RemoteStaticKey []byte
	Cs0             *noise.CipherState // the cipher used by the initiator to send (and the receiver to receive)
	Cs1             *noise.CipherState // the cipher used by the initiator to receive (and the receiver to send)
	Initiator       bool
	queuedMsg       []byte
}

func NewNoiseState(connection Conn, initiator bool, ks KeyStore) (*NoiseState, error) {
	if ks == nil {
		return nil, errors.New("Encryption requires a keystore")
	}

	// set up noise initiator or receiver
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA512)
	// cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	rng := rand.Reader

	static, err := ks.GetLocalKey()
	if err != nil {
		return nil, err
	}

	if static == nil {
		*static, err = cs.GenerateKeypair(rng)
		if err != nil {
			return nil, err
		}

		ks.SetLocalKey(static)
	}

	ns := &NoiseState{
		Cs:             &cs,
		Rng:            rng,
		connection:     connection,
		keyStore:       ks,
		LocalStaticKey: *static,
		Initiator:      initiator,
	}

	ns.RemoteStaticKey, err = ks.GetRemoteKey(connection.RemoteAddr())
	if err != nil {
		return nil, err
	}

	if ns.RemoteStaticKey != nil || !ns.Initiator {
		// we try IK if we're a receiver,
		// or if we are an initiator but know the remote key.
		if err := ns.SetupIK(); err != nil {
			return nil, err
		}
	} else {
		if err := ns.SetupXX(); err != nil {
			return nil, err
		}
	}

	return ns, nil
}

func (ns *NoiseState) SetupXX() error {
	var err error
	ns.Hs, err = noise.NewHandshakeState(noise.Config{
		CipherSuite:   *ns.Cs,
		Random:        ns.Rng,
		Pattern:       noise.HandshakeXX,
		Initiator:     ns.Initiator,
		StaticKeypair: ns.LocalStaticKey,
		// PresharedKey:  srv.Psk,
	})
	if err != nil {
		return err
	}
	ns.PipeState = XX1
	return nil
}

func (ns *NoiseState) SetupIK() error {
	var err error
	var peerStatic []byte;
	if ns.Initiator {
		if ns.RemoteStaticKey == nil {
			return errors.New("Tried to initiate IK handshake without knowing a remote static key!")
		}
		peerStatic = ns.RemoteStaticKey
	}

	ns.Hs, err = noise.NewHandshakeState(noise.Config{
		CipherSuite:   *ns.Cs,
		Random:        ns.Rng,
		Pattern:       noise.HandshakeIK,
		Initiator:     ns.Initiator,
		StaticKeypair: ns.LocalStaticKey,
		PeerStatic:    peerStatic,
		// PresharedKey:  srv.Psk,
	})
	if err != nil {
		return err
	}
	ns.PipeState = IK1
	return nil
}

func (ns *NoiseState) EncryptMessage(msg []byte) ([]byte, error) {
	switch ns.PipeState {
	case XX1: // -> e
		if ns.Initiator {
			ns.queuedMsg = msg
			msg, _, _, err := ns.Hs.WriteMessage(nil, nil)
			if err != nil {
				log.Printf("XX1 handshake encryption failed with %v", err)
				return nil, err
			}
			ns.PipeState++
			return msg, err
		} else {
			return nil, errors.New("Only initiator should send in XX1 handshake")
		}

	case XX2: // <- e, ee, s, es + payload
		if !ns.Initiator {
			// we don't use a payload as this is only ever called in response to an XX1 handshake.
			if msg != nil {
				return nil, errors.New("XX2 should only ever be called with a nil msg")
			}

			_, cs0, cs1, err := ns.Hs.WriteMessage(nil, nil)
			if err != nil {
				log.Printf("XX2 handshake encryption failed with %v", err)
				return nil, err
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1

			// store the remote static key we've just learned about
			ns.keyStore.SetRemoteKey(ns.connection.RemoteAddr(), ns.Hs.PeerStatic())

			ns.PipeState++
			return nil, err
		} else {
			return nil, errors.New("Only receiver should send in XX2 handshake")
		}

	case XX3: // -> s, se + payload
		if ns.Initiator {
			// XXX: do we need to encrypt first? if so, with which CipherState?

			msg, cs0, cs1, err := ns.Hs.WriteMessage(nil, ns.queuedMsg)
			if err != nil {
				log.Printf("XX3 handshake encryption failed with %v", err)
				return nil, err
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState++
			return msg, err
		} else {
			return nil, errors.New("Only initiator should send in XX3 handshake")
		}

	case READY:
		var cs *noise.CipherState
		if ns.Initiator {
			cs = ns.Cs0
		} else {
			cs = ns.Cs1
		}
		msg = cs.Encrypt(nil, nil, msg)
		return msg, nil

	case IK1: // -> e, es, s, ss
		if ns.Initiator {
			// XXX: do we need to encrypt first? if so, with which CipherState?
			msg, cs0, cs1, err := ns.Hs.WriteMessage(nil, msg)
			if err != nil {
				log.Printf("IK1 handshake encryption failed with %v", err)
				return nil, err
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState++
			return msg, err
		} else {
			return nil, errors.New("Only initiator should send in IK1 handshake")
		}

	case IK2: // <- e, ee, se    + payload
		if !ns.Initiator {
			// XXX: do we need to encrypt first?
			msg, cs0, cs1, err := ns.Hs.WriteMessage(nil, msg)
			if err != nil {
				log.Printf("IK2 handshake encryption failed with %v", err)
				return nil, err
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = READY
			return msg, err
		} else {
			return nil, errors.New("Only receiver should send in IK2 handshake")
		}
	}

	return nil, errors.New("Unrecognised pipe state whilst encrypting!")
}

func (ns *NoiseState) DecryptMessage(msg []byte, connUDP *connUDP) ([]byte, error) {
	origMsg := msg

	switch ns.PipeState {
	case XX1: // -> e
		if !ns.Initiator {
			// N.B. this is only ever called during fallback from IK1.

			msg, _, _, err := ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				log.Printf("XX1 handshake decryption failed: %v", err)
				return nil, err
			}
			if msg != nil {
				return nil, errors.New("Received unexpected payload in XX1 handshake")
			}
			ns.PipeState++

			// we now trigger sending an XX2
			res, err := ns.EncryptMessage(nil)
			if err != nil {
				log.Printf("Failed to calculate XX2 response to XX1 with %v", err)
				return nil, err
			}

			_, err = WriteToSessionUDP(connUDP.connection, res, nil)
			if err != nil {
				log.Printf("Failed to send an XX2 response to XX1 with %v", err)
				return nil, err
			}

			return nil, err // XX1s have no payload so we have nothing to decrypt.
		} else {
			return nil, errors.New("Only receiver should receive in XX1 handshake")
		}

	case XX2: // <- e, ee, s, es + payload
		if ns.Initiator {
			msg, _, _, err := ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				log.Printf("XX2 handshake decryption failed with %v", err)
				return nil, err
			}
			if msg != nil {
				return nil, errors.New("Received unexpected payload in XX2 handshake")
			}

			ns.PipeState++

			// at this point we need to trigger a send of the XX3 handshake immediately
			// outside of the CoAP request lifecycle.
			res, err := ns.EncryptMessage(nil)
			if err != nil {
				log.Printf("Failed to calculate XX3 response to XX2 with %v", err)
				return nil, err
			}

			_, err = WriteToSessionUDP(connUDP.connection, res, nil)
			if err != nil {
				log.Printf("Failed to send XX3 response to XX2 with %v", err)
				return nil, err
			}

		} else {
			return nil, errors.New("Only initiator should receive in XX2 handshake")
		}

	case XX3: // -> s, se + payload
		if !ns.Initiator {
			msg, cs0, cs1, err := ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				log.Printf("XX3 handshake decryption failed with %v", err)
				return nil, err
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState++

			// XXX: do we need to decrypt msg before returning?

			return msg, err
		} else {
			return nil, errors.New("Only receiver should receive in XX3 handshake")
		}

	case READY:
		var cs *noise.CipherState
		if ns.Initiator {
			cs = ns.Cs1
		} else {
			cs = ns.Cs0
		}
		msg, err := cs.Decrypt(nil, nil, msg)
		if err != nil {
			log.Printf("Failed to decrypt with %v", err)

			// FIXME: we should switch to state error at this point and re-handshake
		}

		return msg, err

	case IK1: // -> e, es, s, ss + payload
		if !ns.Initiator {
			msg, cs0, cs1, err := ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				log.Printf("IK1 handshake decryption failed with %v", err)
				return nil, err
			}

			msg, err = cs0.Decrypt(nil, nil, msg)
			if err != nil {
				log.Printf("Failed to decrypt IK1 with %v; switching to XXFallback (XX1)", err)
				ns.SetupXX()
				return ns.DecryptMessage(origMsg, connUDP)
			}

			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState++
			return msg, err
		} else {
			return nil, errors.New("Only receiver should receive in IK1 handshake")
		}

	case IK2: // <- e, ee, se    + payload
		if ns.Initiator {
			msg, cs0, cs1, err := ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				log.Printf("IK2 handshake decryption failed with %v", err)
				return nil, err
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = READY

			// XXX: do we need to decrypt msg before returning?

			return msg, err
		} else {
			return nil, errors.New("Only initiator should receive in IK2 handshake")
		}
	}

	return nil, errors.New("Unrecognised pipe state whilst decrypting!")
}
