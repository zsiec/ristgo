package ristgo

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/gre"
	"github.com/zsiec/ristgo/internal/session"
)

// OOBProtocolIP is the default out-of-band GRE protocol type: EtherType 0x0800
// (IPv4), the value libRIST stamps on every out-of-band datagram. A plain WriteOOB
// uses it, and it is the only OOB protocol type that interoperates with libRIST —
// a libRIST peer delivers a 0x0800 GRE frame as out-of-band data but drops any
// other GRE protocol type it does not recognize. Other values therefore tunnel an
// arbitrary protocol between two ristgo peers (which dispatch on it via
// ReadOOBTyped), not to or from libRIST.
const OOBProtocolIP uint16 = gre.ProtoFull

// writeOOBTyped validates a typed OOB write and forwards it to the session. It is
// shared by Sender and Receiver, whose roles both carry the OOB side channel.
func writeOOBTyped(sess *session.Session, proto uint16, p []byte) error {
	if gre.IsReserved(proto) {
		return fmt.Errorf("%w (0x%04X)", ErrOOBProtocol, proto)
	}
	if len(p) > MaxMediaPayload {
		return fmt.Errorf("rist: OOB payload %d bytes exceeds MaxMediaPayload %d", len(p), MaxMediaPayload)
	}
	return sess.WriteOOB(proto, p)
}
