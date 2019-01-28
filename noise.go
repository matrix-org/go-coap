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
	// n.b. we ensure we only have one handshake in flight at time - i.e. one noise pipe

	START NoisePipeState = iota // our starting point

	// if we have no static key for our peer:
	XX1 // -> e
	XX2 // <- e, ee, s, es + payload  (initiator stores s as peer). Payload is empty given the responder has nothing yet to say.
	XX3 // -> s, se        + payload  (responder stores for that peer). Payload is the CoAP req from the initiator.

	// and then we're established.
	READY // send & encrypt via respective CipherStates

	// else, if we have a static key for our peer:
	IK1 // -> e, es, s, ss + payload  (payload is CoAP req)

	// after receiving an IK1 we try to decrypt, and if decryption fails we assume the
	// initiatior is instead trying to talk XX to us and so we treat it as an XX1 and
	// switch to XXfallback instead.

	IK2 // <- e, ee, se    + payload  (payload is CoAP ack)

	// and then we're established again.

	// If something goes wrong...
	ERROR
)

type KeyStore interface {
	GetLocalKey() (noise.DHKey, error)
	SetLocalKey(noise.DHKey) error

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
	Cs0             *noise.CipherState // the cipher used by the initiator to send (and the responder to receive)
	Cs1             *noise.CipherState // the cipher used by the initiator to receive (and the responder to send)
	Initiator       bool
	msgQueue        [][]byte
}

func NewNoiseState(connection Conn, initiator bool, ks KeyStore) (*NoiseState, error) {
	if ks == nil {
		return nil, errors.New("Encryption requires a keystore")
	}

	// set up noise initiator or responder
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA512)
	// cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	rng := rand.Reader

	static, err := ks.GetLocalKey()
	if err != nil {
		return nil, err
	}

	if static.Private == nil {
		static, err = cs.GenerateKeypair(rng)
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
		LocalStaticKey: static,
		Initiator:      initiator,
		msgQueue:       make([][]byte, 0),
	}

	ns.RemoteStaticKey, err = ks.GetRemoteKey(connection.RemoteAddr())
	if err != nil {
		return nil, err
	}

	if ns.RemoteStaticKey != nil || !ns.Initiator {
		// we try IK if we're a responder,
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
	var peerStatic []byte
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

func debugf(format string, args ...interface{}) {
	format = "DEBUG: " + format
	// log.Printf(format, args...)
}

func (ns *NoiseState) EncryptMessage(msg []byte, connUDP *connUDP, sessionUDPData *SessionUDPData) ([]byte, error) {

	// TODO: add IDs of some kind to handshake packets and retry them at this layer
	// in the event of packet loss. This should be handled by the proposed retry
	// layer at the conn layer.
	//
	// See https://noiseprotocol.org/noise.html#out-of-order-transport-messages
	// and 'negotiation data' from
	// https://noiseprotocol.org/noise.html#application-responsibilities
	//
	// See also https://moderncrypto.org/mail-archive/noise/2018/001921.html

	var err error
	var cs0, cs1 *noise.CipherState

	if msg != nil {
		ns.msgQueue = append(ns.msgQueue, msg)
	}

	switch ns.PipeState {
	case XX1: // -> e
		if ns.Initiator {
			debugf("I Sending XX1: -> e")
			msg, _, _, err = ns.Hs.WriteMessage(nil, nil)
			if err != nil {
				return nil, errors.New("XX1 handshake encryption failed with " + err.Error())
			}
			ns.PipeState = XX2
			log.Printf("Sending XX1 handshake message %X", msg)
			return msg, err
		}

		log.Printf("Only initiator should send in XX1 handshake; queuing msg")

	case XX2: // <- e, ee, s, es + payload
		if !ns.Initiator {
			// we don't use a payload as this is only ever called in response to an XX1 handshake.
			debugf("R Sending XX2: <- e, ee, s, es + nil payload")
			msg, cs0, cs1, err = ns.Hs.WriteMessage(nil, nil)
			if err != nil {
				return nil, errors.New("XX2 handshake encryption failed with " + err.Error())
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1

			// store the remote static key we've just learned about
			ns.keyStore.SetRemoteKey(ns.connection.RemoteAddr(), ns.Hs.PeerStatic())

			ns.PipeState = XX3

			return msg, err
		}

		debugf("Only responder should send in XX2 handshake; queuing msg")

	case XX3: // -> s, se + payload
		if ns.Initiator {
			msg, ns.msgQueue = ns.msgQueue[0], ns.msgQueue[1:]
			debugf("I Sending XX3: -> s, se + encrypted payload %v", msg)
			msg, cs0, cs1, err = ns.Hs.WriteMessage(nil, msg)
			if err != nil {
				return nil, errors.New("XX3 handshake encryption failed with " + err.Error())
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = READY

			return msg, err
		}

		debugf("Only initiator should send in XX3 handshake; queuing msg")

	case READY:
		var c noise.Cipher
		if ns.Initiator {
			c = ns.Cs0.Cipher()
		} else {
			c = ns.Cs1.Cipher()
		}

		return c.Encrypt(nil, uint64(connUDP.seqnum), nil, msg), nil

	case IK1: // -> e, es, s, ss  + payload
		if ns.Initiator {
			msg, ns.msgQueue = ns.msgQueue[0], ns.msgQueue[1:]
			debugf("I Sending IK1: -> e, es, s, ss + not-yet-encrypted payload %v", msg)
			msg, cs0, cs1, err = ns.Hs.WriteMessage(nil, msg)
			if err != nil {
				return nil, errors.New("IK1 handshake encryption failed with " + err.Error())
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = IK2

			return msg, err
		}

		debugf("Only initiator should send in IK1 handshake; queuing msg")

	case IK2: // <- e, ee, se    + payload
		if !ns.Initiator {
			msg, ns.msgQueue = ns.msgQueue[0], ns.msgQueue[1:]
			debugf("R Sending IK2: <- e, ee, se + not-yet-encrypted payload %v", msg)
			msg, cs0, cs1, err = ns.Hs.WriteMessage(nil, msg)
			if err != nil {
				return nil, errors.New("IK2 handshake encryption failed with " + err.Error())
			}
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = READY

			return msg, err
		}

		debugf("Only responder should send in IK2 handshake; queuing msg")
	}

	debugf("Unrecognised pipe state %v whilst encrypting!", ns.PipeState)
	return nil, errors.New("unrecognised pipe state whilst encrypting")
}

func (ns *NoiseState) DecryptMessage(msg []byte, remotePipeState NoisePipeState, seqnum uint8, connUDP *connUDP, sessionUDPData *SessionUDPData) (b []byte, toSend []byte, decrypted bool, err error) {
	var res []byte
	var cs0, cs1 *noise.CipherState

	origMsg := msg

	switch remotePipeState {
	case XX1: // -> e
		if !ns.Initiator {
			debugf("Received XX1 handshake message %X", msg)
			// N.B. this is only ever called during fallback from IK1.
			msg, _, _, err = ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				err = errors.New("XX1 handshake decryption failed: " + err.Error())
				return
			}
			if msg != nil {
				err = errors.New("Received unexpected payload in XX1 handshake")
				return
			}
			debugf("R Receiving XX1: <- e")
			ns.PipeState = XX2

			// we now trigger sending an XX2
			res, err = ns.EncryptMessage(nil, connUDP, sessionUDPData)
			if err != nil {
				err = errors.New("Failed to calculate XX2 response to XX1 with " + err.Error())
				return
			}

			return msg, res, false, nil
		}

		err = errors.New("Only responder should receive in XX1 handshake")
		return

	case XX2: // <- e, ee, s, es + payload
		if ns.Initiator {
			msg, _, _, err = ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				err = errors.New("XX2 handshake decryption failed: " + err.Error())
				return
			}
			if msg != nil {
				err = errors.New("Received unexpected payload in XX2 handshake")
				return
			}
			debugf("I Receiving XX2: <- e, ee, s, es + payload %v", msg)

			ns.PipeState = XX3

			// at this point we need to trigger a send of the XX3 handshake immediately
			// outside of the CoAP request lifecycle.
			res, err = ns.EncryptMessage(nil, connUDP, sessionUDPData)
			if err != nil {
				err = errors.New("Failed to calculate XX3 response to XX2 with " + err.Error())
				return
			}

			return msg, res, false, nil
		}

		err = errors.New("Only initiator should receive in XX2 handshake")
		return

	case XX3: // -> s, se + payload
		if !ns.Initiator {
			msg, cs0, cs1, err = ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				err = errors.New("XX3 handshake decryption failed: " + err.Error())
				return
			}
			debugf("R Receiving XX3: -> s, se + decrypted payload %v", msg)
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = READY

			return msg, nil, true, nil
		}

		err = errors.New("Only responder should receive in XX3 handshake")
		return

	case READY:
		var c noise.Cipher
		if ns.Initiator {
			c = ns.Cs1.Cipher()
		} else {
			c = ns.Cs0.Cipher()
		}

		// TODO: take our 8-bit nonce header, derive a full 64-bit nonce from it,
		// and explicitly call SetNonce() on our `cs` so we can reliably decrypt
		// out-of-order or missing messages.  We should also deduplicate at this point
		// to stop replay attacks.
		// See https://noiseprotocol.org/noise.html#out-of-order-transport-messages

		msg, err = c.Decrypt(nil, uint64(seqnum), nil, msg)
		if err != nil {
			err = errors.New("Failed to decrypt: " + err.Error())

			// FIXME: we should probably switch to state ERROR at this point and re-handshake
		}

		return msg, nil, true, err

	case IK1: // -> e, es, s, ss + payload
		if !ns.Initiator {
			msg, cs0, cs1, err = ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				log.Printf("WARN: IK1 handshake decryption failed with %v; switching to XX fallback (XX1)", err)
				ns.SetupXX()
				return ns.DecryptMessage(origMsg, remotePipeState, seqnum, connUDP, sessionUDPData)
			}
			debugf("R Receiving IK1: -> e, es, s, ss + decrypted payload %v", msg)

			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = IK2
			return msg, nil, true, err
		}

		err = errors.New("Only responder should receive in IK1 handshake")
		return

	case IK2: // <- e, ee, se    + payload
		if ns.Initiator {
			msg, cs0, cs1, err = ns.Hs.ReadMessage(nil, msg)
			if err != nil {
				err = errors.New("IK2 handshake decryption failed: " + err.Error())
				return
			}
			debugf("R Receiving IK2: <- e, ee, se + decrypted payload %v", msg)
			ns.Cs0 = cs0
			ns.Cs1 = cs1
			ns.PipeState = READY

			return msg, nil, true, err
		}

		err = errors.New("Only initiator should receive in IK2 handshake")
		return
	}

	log.Printf("Unrecognised pipe state %v whilst decrypting!", ns.PipeState)
	err = errors.New("unrecognised pipe state whilst decrypting")
	return
}
