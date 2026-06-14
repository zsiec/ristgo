package rtcp

import "fmt"

// ParseCompound decodes a UDP datagram holding one or more concatenated
// RTCP packets (TR-06-1 §5.2.1) and returns them in wire order. Framing
// violations anywhere in the datagram — truncation, a non-2 version, a
// length field overrunning the buffer — fail the whole compound; packets
// that frame correctly but are not RIST shapes are returned as Raw entries
// (see the package decoding policy). The returned packets do not alias b.
//
// ParseCompound validates framing only; it does not enforce the RIST
// ordering rules, because a receiver must tolerate peers that order
// differently. BuildCompound enforces ordering on the send side.
func ParseCompound(b []byte) ([]Packet, error) {
	if len(b) == 0 {
		return nil, ErrEmptyCompound
	}
	var pkts []Packet
	for off := 0; off < len(b); {
		pkt, n, err := Parse(b[off:])
		if err != nil {
			return nil, fmt.Errorf("compound offset %d: %w", off, err)
		}
		pkts = append(pkts, pkt)
		off += n
	}
	return pkts, nil
}

// CompoundMarshalSize returns the total encoded size of pkts when
// concatenated into one compound datagram.
func CompoundMarshalSize(pkts []Packet) int {
	size := 0
	for _, p := range pkts {
		size += p.MarshalSize()
	}
	return size
}

// compound ordering classes; a compound must present non-decreasing
// classes after the fixed report+SDES prefix.
const (
	classFeedback = iota // ExtSeq, RangeNACK, BitmaskNACK, Raw (e.g. XR)
	classEcho            // EchoRequest, EchoResponse: always last
)

// BuildCompound appends the RIST compound encoding of pkts to buf and
// returns the extended slice, enforcing the ordering rules of TR-06-1
// §5.2.1 and TR-06-2 §8.4:
//
//  1. The first packet must be a SenderReport, ReceiverReport, or
//     EmptyReceiverReport.
//  2. The second packet must be the (single) SDES/CNAME packet.
//  3. Then any EXTSEQ and NACK packets, where every ExtSeq must be
//     immediately followed by the NACK packet it extends (TR-06-2 §8.4
//     compound stack: RR, CNAME, EXTSEQ, NACK[, EXTSEQ, NACK]). Raw
//     packets (e.g. an XR block, as libRIST inserts in
//     rist_receiver_periodic_rtcp, src/udp.c:678-679) are permitted in
//     this zone.
//  4. Echo Request/Response packets, if any, come last (matching every
//     libRIST compound assembly in src/udp.c:671-857).
//
// On a violation it returns buf unmodified together with an error wrapping
// ErrCompoundOrder. It does not allocate when buf has spare capacity of at
// least CompoundMarshalSize(pkts) bytes.
func BuildCompound(buf []byte, pkts []Packet) ([]byte, error) {
	if err := checkCompoundOrder(pkts); err != nil {
		return buf, err
	}
	for _, p := range pkts {
		buf = p.AppendTo(buf)
	}
	return buf, nil
}

// checkCompoundOrder verifies the RIST compound ordering rules documented
// on BuildCompound.
func checkCompoundOrder(pkts []Packet) error {
	if len(pkts) < 2 {
		return fmt.Errorf("%w: a compound needs a report packet and an SDES packet, got %d packet(s)", ErrCompoundOrder, len(pkts))
	}
	switch pkts[0].(type) {
	case SenderReport, ReceiverReport, EmptyReceiverReport, LinkQualityReport:
	default:
		return fmt.Errorf("%w: first packet must be an SR or (empty) RR, got %T", ErrCompoundOrder, pkts[0])
	}
	if _, ok := pkts[1].(SDES); !ok {
		return fmt.Errorf("%w: second packet must be the SDES/CNAME, got %T", ErrCompoundOrder, pkts[1])
	}

	class := classFeedback
	for i := 2; i < len(pkts); i++ {
		var c int
		switch pkts[i].(type) {
		case ExtSeq:
			// TR-06-2 §8.4: an EXTSEQ qualifies the NACK that follows it.
			if i+1 >= len(pkts) {
				return fmt.Errorf("%w: ExtSeq at position %d is not followed by a NACK packet", ErrCompoundOrder, i)
			}
			switch pkts[i+1].(type) {
			case RangeNACK, BitmaskNACK:
			default:
				return fmt.Errorf("%w: ExtSeq at position %d is not followed by a NACK packet", ErrCompoundOrder, i)
			}
			c = classFeedback
		case RangeNACK, BitmaskNACK, Raw:
			c = classFeedback
		case EchoRequest, EchoResponse:
			c = classEcho
		default:
			return fmt.Errorf("%w: %T is not allowed after the report and SDES packets", ErrCompoundOrder, pkts[i])
		}
		if c < class {
			return fmt.Errorf("%w: %T at position %d must precede the echo packets", ErrCompoundOrder, pkts[i], i)
		}
		class = c
	}
	return nil
}
