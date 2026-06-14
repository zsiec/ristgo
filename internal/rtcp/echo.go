package rtcp

import (
	"encoding/binary"
	"slices"
)

// echoFixedSize is the RTT echo packet without padding: header, SSRC,
// "RIST" name, 64-bit timestamp, and 32-bit processing delay — length=5
// (struct rist_rtcp_echoext, libRIST).
const echoFixedSize = 24

// padTo4 rounds n up to the next multiple of 4.
func padTo4(n int) int { return (n + 3) &^ 3 }

// EchoRequest is the RIST RTT Echo Request of TR-06-1 §5.2.6: an APP packet
// (PT=204, name "RIST") with subtype 2, carrying an arbitrary 64-bit
// timestamp the peer echoes back verbatim. libRIST builds it in
// rist_rtcp_write_echoreq with flags
// RTCP_ECHOEXT_REQ_FLAGS (0x82).
//
// The wire format also carries a 32-bit Processing Delay field, but in
// requests TR-06-1 requires the sender to zero-fill it and the receiver to
// ignore it, so the type does not expose it: encoders write zero and
// decoders discard whatever arrived.
type EchoRequest struct {
	// SSRC is the "SSRC of media source" the measurement relates to,
	// used as in the range NACK (TR-06-1 §5.2.6).
	SSRC uint32

	// Timestamp is an arbitrary 64-bit value echoed back verbatim by the
	// responder. NTP-64 format is suggested for debuggability but not
	// required.
	Timestamp uint64

	// Padding is optional extra payload so RTT can be measured with
	// media-sized packets. TR-06-1 requires a multiple of 4 bytes;
	// encoders zero-fill up to the next 32-bit boundary if it is not.
	// padTo4(len(Padding))/4 must not exceed 65530 or the 16-bit length
	// field overflows — never an issue at any real MTU.
	Padding []byte
}

// MarshalSize returns the encoded size: 24 bytes plus the padding rounded
// up to a multiple of 4.
func (p EchoRequest) MarshalSize() int { return echoFixedSize + padTo4(len(p.Padding)) }

// AppendTo appends the encoding to buf and returns the extended slice.
func (p EchoRequest) AppendTo(buf []byte) []byte {
	return appendEcho(buf, AppSubtypeEchoRequest, p.SSRC, p.Timestamp, 0, p.Padding)
}

func (EchoRequest) isPacket() {}

// EchoResponse is the RIST RTT Echo Response of TR-06-1 §5.2.6: subtype 3,
// echoing the request's timestamp verbatim plus the responder's processing
// delay. libRIST builds it in rist_rtcp_write_echoresp with flags
// RTCP_ECHOEXT_RESP_FLAGS (0x83).
type EchoResponse struct {
	// SSRC is the "SSRC of media source" the measurement relates to.
	SSRC uint32

	// Timestamp is the requester's timestamp, copied verbatim from the
	// EchoRequest without processing or interpretation.
	Timestamp uint64

	// ProcessingDelay is the time in microseconds between receiving the
	// request and transmitting this response; the requester subtracts it
	// from its round-trip measurement. Zero means "responded immediately".
	ProcessingDelay uint32

	// Padding echoes the request's padding bytes (TR-06-1 §5.2.6: the
	// response shall carry at least as much padding as the request, MTU
	// permitting). Encoders zero-fill to a multiple of 4 if needed. The same
	// 65530-word ceiling as EchoRequest.Padding applies.
	Padding []byte
}

// MarshalSize returns the encoded size: 24 bytes plus the padding rounded
// up to a multiple of 4.
func (p EchoResponse) MarshalSize() int { return echoFixedSize + padTo4(len(p.Padding)) }

// AppendTo appends the encoding to buf and returns the extended slice.
func (p EchoResponse) AppendTo(buf []byte) []byte {
	return appendEcho(buf, AppSubtypeEchoResponse, p.SSRC, p.Timestamp, p.ProcessingDelay, p.Padding)
}

func (EchoResponse) isPacket() {}

// appendEcho encodes either echo subtype. The length field is 5 + X/4 for X
// padding bytes (TR-06-1 §5.2.6).
func appendEcho(buf []byte, subtype byte, ssrc uint32, ts uint64, delay uint32, padding []byte) []byte {
	pad := padTo4(len(padding))
	buf = appendHeader(buf, subtype, PTApp, uint16(5+pad/4))
	buf, w := grow(buf, echoFixedSize-headerSize+pad)
	binary.BigEndian.PutUint32(w[0:4], ssrc)
	binary.BigEndian.PutUint32(w[4:8], NameRIST)
	binary.BigEndian.PutUint64(w[8:16], ts)
	binary.BigEndian.PutUint32(w[16:20], delay)
	n := copy(w[20:], padding)
	for i := 20 + n; i < len(w); i++ {
		w[i] = 0
	}
	return buf
}

// decodeEcho decodes an APP "RIST" packet of subtype 2 or 3. The caller has
// already verified the fixed APP prefix and name.
func decodeEcho(subtype byte, body []byte) (Packet, bool) {
	if len(body) < echoFixedSize {
		return nil, false
	}
	ssrc := binary.BigEndian.Uint32(body[4:8])
	ts := binary.BigEndian.Uint64(body[12:20])
	padding := slices.Clone(body[echoFixedSize:])
	if len(padding) == 0 {
		padding = nil
	}
	if subtype == AppSubtypeEchoRequest {
		// The request's delay field is ignored per TR-06-1 §5.2.6 and
		// re-encodes as zero.
		return EchoRequest{SSRC: ssrc, Timestamp: ts, Padding: padding}, true
	}
	return EchoResponse{
		SSRC:            ssrc,
		Timestamp:       ts,
		ProcessingDelay: binary.BigEndian.Uint32(body[20:24]),
		Padding:         padding,
	}, true
}
