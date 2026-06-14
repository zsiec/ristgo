package dtls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The DTLS handshake message layer (RFC 6347 §4.2.2): a 12-byte header carrying a
// message sequence and fragment coordinates, so a large handshake message can be
// fragmented across datagrams and reassembled in order on the receiver.

// handshakeHeaderLen is msg_type(1) + length(3) + message_seq(2) +
// fragment_offset(3) + fragment_length(3).
const handshakeHeaderLen = 12

// maxHandshakeBody bounds a reassembled handshake message so a hostile length
// field cannot force a large allocation. Certificates (the largest legitimate
// message here) are a few KB; 64 KiB is generous and safe.
const maxHandshakeBody = 1 << 16

// maxPendingMessages bounds how many distinct future message_seq entries the
// reassembler buffers ahead of the in-order delivery cursor. A DTLS flight is a
// small, fixed number of messages (RFC 6347 §4.2.4 reassembly is windowed), so
// a peer that declares many distinct future seqs is hostile: handshake
// fragments arrive as unauthenticated epoch-0 plaintext, and each new seq
// allocates up to maxHandshakeBody. Without this window a single MTU datagram
// of fragments with distinct seqs could force megabytes of pending allocation,
// a handshake-time memory-exhaustion DoS. With it, pending allocation is capped
// at maxPendingMessages * maxHandshakeBody.
const maxPendingMessages = 8

// handshakeMessage is one fully reassembled handshake message.
type handshakeMessage struct {
	typ  handshakeType
	seq  uint16
	body []byte
}

// marshal frames the message as a single unfragmented handshake record body
// (fragment_offset 0, fragment_length == length), appended to dst.
func (m handshakeMessage) marshal(dst []byte) []byte {
	return appendHandshakeFragment(dst, m.typ, m.seq, len(m.body), 0, m.body)
}

// fullMessageBytes returns the canonical unfragmented encoding (header + body)
// used to feed the running handshake transcript hash. The transcript always
// hashes the reassembled, unfragmented form regardless of how it was sent or
// received (RFC 6347 §4.2.6).
func (m handshakeMessage) fullMessageBytes() []byte {
	return m.marshal(nil)
}

// appendHandshakeFragment appends one handshake fragment (12-byte header + the
// fragment slice) to dst.
func appendHandshakeFragment(dst []byte, typ handshakeType, seq uint16, totalLen, fragOff int, frag []byte) []byte {
	dst = append(dst, byte(typ))
	dst = appendUint24(dst, uint32(totalLen))
	dst = binary.BigEndian.AppendUint16(dst, seq)
	dst = appendUint24(dst, uint32(fragOff))
	dst = appendUint24(dst, uint32(len(frag)))
	return append(dst, frag...)
}

// fragmentMessage splits a full handshake message body into fragments whose
// header+body each fit within maxFragment bytes, returning each fragment's
// complete handshake encoding (header included). A message that fits is returned
// as a single fragment.
func fragmentMessage(typ handshakeType, seq int, body []byte, maxFragment int) [][]byte {
	avail := maxFragment - handshakeHeaderLen
	if avail < 1 {
		avail = 1
	}
	var out [][]byte
	for off := 0; off < len(body) || off == 0 && len(body) == 0; off += avail {
		end := off + avail
		if end > len(body) {
			end = len(body)
		}
		out = append(out, appendHandshakeFragment(nil, typ, uint16(seq), len(body), off, body[off:end]))
		if len(body) == 0 {
			break
		}
	}
	return out
}

// parsedFragment is one decoded handshake fragment header plus its slice.
type parsedFragment struct {
	typ      handshakeType
	totalLen int
	seq      uint16
	fragOff  int
	frag     []byte
}

// parseHandshakeFragment decodes one handshake fragment from the front of b,
// returning it and the bytes consumed. It never panics on arbitrary input.
func parseHandshakeFragment(b []byte) (parsedFragment, int, error) {
	if len(b) < handshakeHeaderLen {
		return parsedFragment{}, 0, errShortRecord
	}
	totalLen := int(uint24(b[1:4]))
	fragOff := int(uint24(b[6:9]))
	fragLen := int(uint24(b[9:12]))
	if totalLen > maxHandshakeBody {
		return parsedFragment{}, 0, fmt.Errorf("rist: dtls: handshake length %d exceeds %d", totalLen, maxHandshakeBody)
	}
	end := handshakeHeaderLen + fragLen
	if len(b) < end {
		return parsedFragment{}, 0, errShortRecord
	}
	if fragOff+fragLen > totalLen {
		return parsedFragment{}, 0, errors.New("rist: dtls: handshake fragment exceeds message length")
	}
	return parsedFragment{
		typ:      handshakeType(b[0]),
		totalLen: totalLen,
		seq:      binary.BigEndian.Uint16(b[4:6]),
		fragOff:  fragOff,
		frag:     b[handshakeHeaderLen:end],
	}, end, nil
}

// reassembler buffers incoming handshake fragments and yields complete messages
// in strict message_seq order, dropping duplicates and tolerating reordering and
// fragmentation (RFC 6347 §4.2.4, §4.2.6). It is not safe for concurrent use.
type reassembler struct {
	next    uint16
	pending map[uint16]*partialMessage
}

type partialMessage struct {
	typ      handshakeType
	totalLen int
	body     []byte
	received []bool // per-byte coverage
	have     int    // count of covered bytes
}

func newReassembler() *reassembler {
	return &reassembler{pending: make(map[uint16]*partialMessage)}
}

// accept ingests one fragment. Fragments for already-delivered messages (seq <
// next) and out-of-window future fragments are ignored. It returns an error only
// on an internally inconsistent fragment (type/length mismatch within a seq).
func (r *reassembler) accept(f parsedFragment) error {
	if f.seq < r.next {
		return nil // already delivered; ignore retransmission
	}
	// Drop fragments beyond the reassembly window so a hostile peer cannot pin
	// memory by declaring many distinct future message_seq values. f.seq >= next
	// holds here, so the uint16 gap is the simple forward distance.
	if f.seq-r.next >= maxPendingMessages {
		return nil
	}
	p := r.pending[f.seq]
	if p == nil {
		p = &partialMessage{
			typ:      f.typ,
			totalLen: f.totalLen,
			body:     make([]byte, f.totalLen),
			received: make([]bool, f.totalLen),
		}
		r.pending[f.seq] = p
	}
	if p.typ != f.typ || p.totalLen != f.totalLen {
		return errors.New("rist: dtls: inconsistent handshake fragment for message_seq")
	}
	copy(p.body[f.fragOff:], f.frag)
	for i := f.fragOff; i < f.fragOff+len(f.frag); i++ {
		if !p.received[i] {
			p.received[i] = true
			p.have++
		}
	}
	return nil
}

// nextMessage returns the next in-order fully reassembled message if available,
// advancing the delivery cursor. ok is false when the next message is still
// incomplete or unseen.
func (r *reassembler) nextMessage() (handshakeMessage, bool) {
	p := r.pending[r.next]
	if p == nil || p.have != p.totalLen {
		return handshakeMessage{}, false
	}
	msg := handshakeMessage{typ: p.typ, seq: r.next, body: p.body}
	delete(r.pending, r.next)
	r.next++
	return msg, true
}

// appendUint24 appends the low 24 bits of v big-endian.
func appendUint24(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>16), byte(v>>8), byte(v))
}

// uint24 reads a 24-bit big-endian integer from b (>= 3 bytes).
func uint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}
