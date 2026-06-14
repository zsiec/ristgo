// RIST retransmission SSRC marking.
//
// RIST does not use RFC 4588 retransmission payloads. A retransmitted packet
// is the ORIGINAL RTP packet — same sequence number, same timestamp, same
// payload — distinguished only by the SSRC least-significant bit:
//
//   - The base flow SSRC (libRIST "flow id") must be even. libRIST rejects
//     odd flow ids ("Flow ID must be an even number!") and forces the LSB
//     clear when setting one ("flow_id &= ~1UL").
//   - The sender marks a retransmission by setting the SSRC LSB
//     ("hdr->rtp.ssrc = htobe32(p->adv_flow_id | 0x01)").
//   - The receiver detects a retransmission by testing the LSB and clears it
//     to recover the flow SSRC ("if (flow_id & 1UL) { flow_id ^= 1UL;
//     retry = 1; }").

package rtp

// NormalizeSSRC returns ssrc with its least-significant bit forced to zero,
// yielding the base flow SSRC. RIST base flow SSRCs must be even because the
// LSB is reserved as the retransmission marker (flow_id &= ~1UL). Applying it
// to a retransmit-marked SSRC recovers the original flow SSRC, exactly as the
// libRIST receiver does (flow_id ^= 1UL after the LSB test).
func NormalizeSSRC(ssrc uint32) uint32 {
	return ssrc &^ 1
}

// MarkRetransmit returns ssrc with its least-significant bit set, marking a
// retransmitted packet (hdr->rtp.ssrc = htobe32(p->adv_flow_id | 0x01)). The
// retransmission carries the original packet unchanged — same sequence number,
// timestamp, and payload; this bit is the only difference. This is NOT
// RFC 4588.
func MarkRetransmit(ssrc uint32) uint32 {
	return ssrc | 1
}

// IsRetransmit reports whether ssrc has its least-significant bit set, i.e.
// whether the packet carrying it is a RIST retransmission (if (flow_id & 1UL)).
// Use NormalizeSSRC to recover the base flow SSRC from a retransmit-marked one.
func IsRetransmit(ssrc uint32) bool {
	return ssrc&1 != 0
}
