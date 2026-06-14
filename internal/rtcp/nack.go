package rtcp

import "encoding/binary"

// Portions of the bitmask-NACK FCI packing/unpacking logic in this file
// (nackPairsFromSequenceNumbers and NackPair iteration) are ported and
// adapted from pion/rtcp's TransportLayerNack (transport_layer_nack.go),
// MIT License, Copyright (c) The Pion community <https://pion.ly>.
// See NOTICE.md for the full license text.

// MaxNackRecordsPerPacket is the record budget the seam encoders apply to a
// single NACK packet. TR-06-1 §5.3.2.2 mandates at most 16 range requests
// per range NACK; §5.3.2.3 recommends the same bound for bitmask FCIs, and
// the seam applies it to both encodings. libRIST does not split on the send
// side — rist_receiver_send_nacks packs the whole seq array into one packet —
// so the decoders here intentionally accept arbitrarily long NACK packets
// (record count is driven by the length field); only the encoders apply this
// bound.
const MaxNackRecordsPerPacket = 16

// NackRange is one Packet Range Request of TR-06-1 §5.3.2.2 (struct
// rist_rtp_nack_record, libRIST): packets Start through Start+Extra inclusive
// (mod 2^16) are being requested.
type NackRange struct {
	// Start is the RTP sequence number of the first packet in the missing
	// block.
	Start uint16

	// Extra is the number of ADDITIONAL contiguous missing packets after
	// Start; zero requests only Start itself.
	Extra uint16
}

// RangeNACK is the RIST range-based retransmission request of TR-06-1
// §5.3.2.2: an APP packet (PT=204, subtype 0, name "RIST") whose body is a
// list of NackRange records. libRIST builds it in rist_receiver_send_nacks
// with flags RTCP_NACK_RANGE_FLAGS (0x80).
type RangeNACK struct {
	// MediaSSRC is the "SSRC of media source" of the stream the request
	// relates to — the packet's only SSRC field (TR-06-1 re-defines the
	// APP SSRC/CSRC field this way; see §5.3.2.2 footnote). Either LSB
	// variant of the SSRC is acceptable.
	MediaSSRC uint32

	// Ranges holds the range records. AppendTo writes a 16-bit length field
	// of 2+len(Ranges), so len(Ranges) must not exceed 65533 or that field
	// overflows; the seam encoder (EncodeRangeNACK) splits far below that at
	// MaxNackRecordsPerPacket.
	Ranges []NackRange
}

// MarshalSize returns the encoded size: 12 bytes plus 4 per range record.
func (p RangeNACK) MarshalSize() int { return appFixedSize + 4*len(p.Ranges) }

// AppendTo appends the encoding to buf and returns the extended slice. The
// length field is n+2 for n range records (TR-06-1 §5.3.2.2).
func (p RangeNACK) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, AppSubtypeRangeNACK, PTApp, uint16(2+len(p.Ranges)))
	buf, w := grow(buf, appFixedSize-headerSize+4*len(p.Ranges))
	binary.BigEndian.PutUint32(w[0:4], p.MediaSSRC)
	binary.BigEndian.PutUint32(w[4:8], NameRIST)
	for i, r := range p.Ranges {
		binary.BigEndian.PutUint16(w[8+4*i:], r.Start)
		binary.BigEndian.PutUint16(w[10+4*i:], r.Extra)
	}
	return buf
}

func (RangeNACK) isPacket() {}

// MissingSeqs expands the range records into the full list of requested
// sequence numbers, in record order, wrapping at the 16-bit boundary. The
// values are 16-bit sequence numbers widened to uint32 by the session (or
// by a preceding ExtSeq packet's SeqHigh).
func (p RangeNACK) MissingSeqs() []uint32 {
	return p.AppendMissingSeqs(nil)
}

// AppendMissingSeqs appends the expanded sequence list to dst and returns
// the extended slice, allocating only if dst lacks capacity.
func (p RangeNACK) AppendMissingSeqs(dst []uint32) []uint32 {
	for _, r := range p.Ranges {
		s := r.Start
		for i := uint32(0); i <= uint32(r.Extra); i++ {
			dst = append(dst, uint32(s))
			s++ // natural uint16 wrap: 65535 -> 0
		}
	}
	return dst
}

// decodeRangeNACK decodes an APP "RIST" packet of subtype 0. The caller has
// already verified the fixed APP prefix and name; the record count follows
// from the (already validated) length field.
func decodeRangeNACK(body []byte) (Packet, bool) {
	n := (len(body) - appFixedSize) / 4
	p := RangeNACK{MediaSSRC: binary.BigEndian.Uint32(body[4:8])}
	if n > 0 {
		p.Ranges = make([]NackRange, n)
		for i := range p.Ranges {
			p.Ranges[i].Start = binary.BigEndian.Uint16(body[appFixedSize+4*i:])
			p.Ranges[i].Extra = binary.BigEndian.Uint16(body[appFixedSize+4*i+2:])
		}
	}
	return p, true
}

// NackPair is one Generic NACK FCI of RFC 4585 §6.2.1 / TR-06-1 §5.3.2.1:
// a starting packet ID plus a 16-bit bitmask covering the 16 packets after
// it.
type NackPair struct {
	// PID is the RTP sequence number of a lost packet.
	PID uint16

	// BLP is the bitmask of following lost packets: bit i (LSB = bit 0)
	// set means packet PID+i+1 (mod 2^16) is also lost. A clear bit makes
	// no claim that the packet was received.
	BLP uint16
}

// AppendSeqs appends the up-to-17 sequence numbers the pair requests (PID
// first, then each set BLP bit) to dst and returns the extended slice.
func (n NackPair) AppendSeqs(dst []uint32) []uint32 {
	dst = append(dst, uint32(n.PID))
	for i := uint16(0); i < 16; i++ {
		if n.BLP&(1<<i) != 0 {
			dst = append(dst, uint32(n.PID+i+1)) // uint16 wrap
		}
	}
	return dst
}

// BitmaskNACK is the bitmask-based retransmission request of TR-06-1
// §5.3.2.1: the RFC 4585 Generic NACK, PT=205, FMT=1, with sender and media
// SSRCs followed by Generic NACK FCIs. It is the same wire format as pion
// rtcp's TransportLayerNack. libRIST builds it in rist_receiver_send_nacks
// with flags RTCP_NACK_BITMASK_FLAGS (0x81).
type BitmaskNACK struct {
	// SenderSSRC identifies the originator of this packet. TR-06-1
	// §5.3.2.1 has the RIST sender ignore it, and libRIST transmits zero.
	SenderSSRC uint32

	// MediaSSRC is the SSRC of the media stream the request relates to.
	// Either LSB variant of the SSRC is acceptable.
	MediaSSRC uint32

	// FCIs holds the Generic NACK fields. AppendTo writes a 16-bit length
	// field of 2+len(FCIs), so len(FCIs) must not exceed 65533 or that field
	// overflows; the seam encoder (EncodeBitmaskNACK) splits far below that at
	// MaxNackRecordsPerPacket.
	FCIs []NackPair
}

// MarshalSize returns the encoded size: 12 bytes plus 4 per FCI.
func (p BitmaskNACK) MarshalSize() int { return appFixedSize + 4*len(p.FCIs) }

// AppendTo appends the encoding to buf and returns the extended slice. The
// length field is n+2 for n FCIs (TR-06-1 §5.3.2.1).
func (p BitmaskNACK) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, FMTGenericNACK, PTTransportFeedback, uint16(2+len(p.FCIs)))
	buf, w := grow(buf, appFixedSize-headerSize+4*len(p.FCIs))
	binary.BigEndian.PutUint32(w[0:4], p.SenderSSRC)
	binary.BigEndian.PutUint32(w[4:8], p.MediaSSRC)
	for i, f := range p.FCIs {
		binary.BigEndian.PutUint16(w[8+4*i:], f.PID)
		binary.BigEndian.PutUint16(w[10+4*i:], f.BLP)
	}
	return buf
}

func (BitmaskNACK) isPacket() {}

// MissingSeqs expands the FCIs into the full list of requested sequence
// numbers, in FCI order, wrapping at the 16-bit boundary. The values are
// 16-bit sequence numbers widened to uint32 by the session.
func (p BitmaskNACK) MissingSeqs() []uint32 {
	return p.AppendMissingSeqs(nil)
}

// AppendMissingSeqs appends the expanded sequence list to dst and returns
// the extended slice, allocating only if dst lacks capacity.
func (p BitmaskNACK) AppendMissingSeqs(dst []uint32) []uint32 {
	for _, f := range p.FCIs {
		dst = f.AppendSeqs(dst)
	}
	return dst
}

// decodeBitmaskNACK decodes a PT=205 packet. Only FMT=1 (Generic NACK) is a
// RIST shape; other transport-layer feedback formats fall back to Raw.
func decodeBitmaskNACK(h header, body []byte) (Packet, bool) {
	if h.count != FMTGenericNACK || h.size < appFixedSize {
		return nil, false
	}
	n := (h.size - appFixedSize) / 4
	p := BitmaskNACK{
		SenderSSRC: binary.BigEndian.Uint32(body[4:8]),
		MediaSSRC:  binary.BigEndian.Uint32(body[8:12]),
	}
	if n > 0 {
		p.FCIs = make([]NackPair, n)
		for i := range p.FCIs {
			p.FCIs[i].PID = binary.BigEndian.Uint16(body[appFixedSize+4*i:])
			p.FCIs[i].BLP = binary.BigEndian.Uint16(body[appFixedSize+4*i+2:])
		}
	}
	return p, true
}

// EncodeRangeNACK packs missing — 16-bit sequence numbers (widened values
// must be narrowed by the session first) in ascending circular order — into
// the minimal list of range records, split into packets of at most
// MaxNackRecordsPerPacket records. A run of consecutive (mod 2^16) numbers
// becomes a single {start, extra} record, exactly like libRIST's range
// encoder, including across the 65535->0 wrap.
//
// senderSSRC is accepted for signature symmetry with EncodeBitmaskNACK
// (mirroring libRIST's seq-array dispatch seam in rist_receiver_send_nacks)
// but is unused: the range NACK wire format carries only the media SSRC.
// Only the low 16 bits of each missing value are used. An empty missing
// list yields nil.
func EncodeRangeNACK(senderSSRC, mediaSSRC uint32, missing []uint32) []RangeNACK {
	if len(missing) == 0 {
		return nil
	}
	var (
		pkts   []RangeNACK
		ranges []NackRange
		cur    = NackRange{Start: uint16(missing[0])}
		last   = uint16(missing[0])
	)
	flushRange := func() {
		ranges = append(ranges, cur)
		if len(ranges) == MaxNackRecordsPerPacket {
			pkts = append(pkts, RangeNACK{MediaSSRC: mediaSSRC, Ranges: ranges})
			ranges = nil
		}
	}
	for _, m := range missing[1:] {
		s := uint16(m)
		// cur.Extra == 65535 would mean the record already spans the whole
		// ring; libRIST splits there too.
		if s == last+1 && cur.Extra < 0xFFFF {
			cur.Extra++
		} else {
			flushRange()
			cur = NackRange{Start: s}
		}
		last = s
	}
	flushRange()
	if len(ranges) > 0 {
		pkts = append(pkts, RangeNACK{MediaSSRC: mediaSSRC, Ranges: ranges})
	}
	return pkts
}

// EncodeBitmaskNACK packs missing — 16-bit sequence numbers (widened values
// must be narrowed by the session first) in ascending circular order — into
// the minimal list of Generic NACK FCIs, split into packets of at most
// MaxNackRecordsPerPacket FCIs. Each FCI covers its PID plus the 16
// following sequence numbers via the BLP bitmask, wrapping at 65535->0.
//
// Only the low 16 bits of each missing value are used. An empty missing
// list yields nil.
func EncodeBitmaskNACK(senderSSRC, mediaSSRC uint32, missing []uint32) []BitmaskNACK {
	if len(missing) == 0 {
		return nil
	}
	var pkts []BitmaskNACK
	for _, pair := range nackPairsFromSequenceNumbers(missing) {
		if len(pkts) == 0 || len(pkts[len(pkts)-1].FCIs) == MaxNackRecordsPerPacket {
			pkts = append(pkts, BitmaskNACK{SenderSSRC: senderSSRC, MediaSSRC: mediaSSRC})
		}
		p := &pkts[len(pkts)-1]
		p.FCIs = append(p.FCIs, pair)
	}
	return pkts
}

// nackPairsFromSequenceNumbers packs sequence numbers in ascending circular
// order into minimal NackPairs. Ported and adapted from pion/rtcp
// NackPairsFromSequenceNumbers (transport_layer_nack.go, MIT License): the
// uint16 subtraction m-pid makes the 17-packet window test wrap-correct at
// the 65535->0 boundary.
func nackPairsFromSequenceNumbers(missing []uint32) []NackPair {
	if len(missing) == 0 {
		return nil
	}
	pairs := make([]NackPair, 0, 1)
	cur := NackPair{PID: uint16(missing[0])}
	for _, m := range missing[1:] {
		s := uint16(m)
		if d := s - cur.PID; d >= 1 && d <= 16 {
			cur.BLP |= 1 << (d - 1)
		} else {
			pairs = append(pairs, cur)
			cur = NackPair{PID: s}
		}
	}
	return append(pairs, cur)
}

// DecodeNACK returns the full sequence list requested by a NACK packet of
// either encoding, in packet order (ascending circular order when the
// packet came from a conforming encoder). The values are 16-bit sequence
// numbers in uint32 slots, widened to 32 bits later by the session. The
// second return is false when pkt is not a NACK packet.
func DecodeNACK(pkt Packet) ([]uint32, bool) {
	switch p := pkt.(type) {
	case RangeNACK:
		return p.MissingSeqs(), true
	case BitmaskNACK:
		return p.MissingSeqs(), true
	}
	return nil, false
}
