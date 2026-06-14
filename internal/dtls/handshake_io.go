package dtls

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// Shared handshake plumbing: outgoing flight assembly + retransmission, the
// in-order handshake message read pump, and the transcript hash.

var errHandshakeTimeout = errors.New("rist: dtls: handshake timed out")

// recordSpec is one record to emit in a flight: its content type, the epoch it
// is protected under (0 = plaintext), and its payload (a handshake fragment
// including its 12-byte header, a CCS byte, or a Finished message body).
type recordSpec struct {
	typ     contentType
	epoch   uint16
	payload []byte
}

// flight is one logical group of records sent together and retransmitted as a
// unit on timeout (RFC 6347 §4.2.4).
type flight struct {
	specs []recordSpec
}

// emitHandshake appends a handshake message to f: it allocates the next outgoing
// message_seq, optionally adds the canonical unfragmented form to the transcript
// (the cookieless ClientHello and the HelloVerifyRequest are excluded,
// RFC 6347 §4.2.6), and fragments the body into record specs at the given epoch.
func (c *Conn) emitHandshake(f *flight, typ handshakeType, epoch uint16, body []byte, inTranscript bool) {
	seq := c.sendMsgSeq
	c.sendMsgSeq++
	if inTranscript {
		c.transcript = append(c.transcript, handshakeMessage{typ: typ, seq: seq, body: body}.fullMessageBytes()...)
	}
	for _, frag := range fragmentMessage(typ, int(seq), body, maxDatagram-recordHeaderLen) {
		f.specs = append(f.specs, recordSpec{typ: recordHandshake, epoch: epoch, payload: frag})
	}
}

// emitCCS appends a ChangeCipherSpec record (always epoch 0, RFC 5246 §7.1).
func emitCCS(f *flight) {
	f.specs = append(f.specs, recordSpec{typ: recordChangeCipherSpec, epoch: 0, payload: []byte{1}})
}

// addToTranscript appends a received handshake message's canonical form to the
// transcript hash input.
func (c *Conn) addToTranscript(m handshakeMessage) {
	c.transcript = append(c.transcript, m.fullMessageBytes()...)
}

// transcriptHash returns SHA-256 over the handshake transcript so far — the seed
// for the master secret (EMS), CertificateVerify, and Finished verify_data.
func (c *Conn) transcriptHash() []byte {
	sum := sha256.Sum256(c.transcript)
	return sum[:]
}

// sendFlight records f as the retransmission unit, resets the retransmit timer,
// and transmits it.
func (c *Conn) sendFlight(f *flight) error {
	c.lastFlight = f
	c.curRetrans = c.cfg.RetransmitTimeout
	return c.transmit(f)
}

// transmit writes a flight's records to the wire, packing several records per
// datagram up to maxDatagram and assigning each a fresh record sequence number
// (retransmissions reuse the flight but get new sequence numbers,
// RFC 6347 §4.2.4).
func (c *Conn) transmit(f *flight) error {
	var dg []byte
	flush := func() error {
		if len(dg) == 0 {
			return nil
		}
		_, err := c.transport.Write(dg)
		dg = dg[:0]
		return err
	}
	for _, spec := range f.specs {
		seq := c.nextSeq(spec.epoch)
		fragment := spec.payload
		if spec.epoch > 0 {
			if !c.keysReady {
				return errors.New("rist: dtls: flight needs encryption before keys")
			}
			fragment = c.sealHalf(spec.epoch).seal(spec.epoch, seq, spec.typ, versionDTLS12, spec.payload)
		}
		rec := record{typ: spec.typ, version: versionDTLS12, epoch: spec.epoch, seq: seq, fragment: fragment}
		marshalled := rec.marshal(nil)
		if len(dg)+len(marshalled) > maxDatagram {
			if err := flush(); err != nil {
				return err
			}
		}
		dg = append(dg, marshalled...)
	}
	return flush()
}

// retransmit resends the last flight with fresh record sequence numbers.
func (c *Conn) retransmit() error {
	if c.lastFlight == nil {
		return nil
	}
	return c.transmit(c.lastFlight)
}

// readHandshakeMessage returns the next in-order, fully reassembled handshake
// message before the overall deadline. It transparently decrypts epoch-1 records
// (the encrypted Finished), advances the receive epoch on ChangeCipherSpec,
// drops duplicates and malformed fragments, surfaces a peer fatal alert, and
// retransmits our last flight on a read timeout with exponential backoff.
func (c *Conn) readHandshakeMessage(overall time.Time) (handshakeMessage, error) {
	for {
		if msg, ok := c.reasm.nextMessage(); ok {
			return msg, nil
		}
		if len(c.pendingRecords) == 0 {
			rdl := time.Now().Add(c.curRetrans)
			if rdl.After(overall) {
				rdl = overall
			}
			recs, err := c.readDatagram(rdl)
			if err != nil {
				if isTimeout(err) {
					if !time.Now().Before(overall) {
						return handshakeMessage{}, errHandshakeTimeout
					}
					if rerr := c.retransmit(); rerr != nil {
						return handshakeMessage{}, rerr
					}
					if c.curRetrans *= 2; c.curRetrans > 60*time.Second {
						c.curRetrans = 60 * time.Second
					}
					continue
				}
				return handshakeMessage{}, err
			}
			c.pendingRecords = recs
		}
		for len(c.pendingRecords) > 0 {
			r := c.pendingRecords[0]
			c.pendingRecords = c.pendingRecords[1:]
			if err := c.processHandshakeRecord(r); err != nil {
				return handshakeMessage{}, err
			}
			if msg, ok := c.reasm.nextMessage(); ok {
				return msg, nil
			}
		}
	}
}

// processHandshakeRecord routes one record during the handshake into the
// reassembler (handshake), the epoch advance (CCS), or an error (fatal alert).
func (c *Conn) processHandshakeRecord(r record) error {
	switch r.typ {
	case recordChangeCipherSpec:
		c.peerCCS = true
		c.recvEpoch = 1
		return nil
	case recordAlert:
		payload := r.fragment
		if r.epoch > 0 {
			pt, ok := c.decryptRecord(r)
			if !ok {
				return nil
			}
			payload = pt
		}
		if len(payload) >= 2 && alertLevel(payload[0]) == alertFatal {
			return fmt.Errorf("rist: dtls: peer fatal alert %d", payload[1])
		}
		return nil
	case recordHandshake:
		frag := r.fragment
		if r.epoch > 0 {
			pt, ok := c.decryptRecord(r)
			if !ok {
				return nil // not yet decryptable; drop
			}
			frag = pt
		}
		for len(frag) > 0 {
			pf, n, err := parseHandshakeFragment(frag)
			if err != nil {
				return nil // ignore malformed trailing bytes
			}
			if err := c.reasm.accept(pf); err != nil {
				return nil
			}
			frag = frag[n:]
		}
		return nil
	default:
		return nil
	}
}

// sendAlert writes a best-effort fatal alert (plaintext, epoch 0) before the
// handshake fails, so a peer learns the reason rather than just timing out.
func (c *Conn) sendAlert(desc uint8) {
	_ = c.writeRecord(recordAlert, 0, []byte{byte(alertFatal), desc})
}
