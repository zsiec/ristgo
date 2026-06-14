package dtls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The DTLS 1.2 record layer (RFC 6347 §4.1). Every record carries an explicit
// 16-bit epoch and 48-bit sequence number (TLS leaves both implicit), so a
// record is self-describing on a lossy, reordering datagram transport.

// contentType is the record content type (RFC 5246 §6.2.1).
type contentType uint8

const (
	recordChangeCipherSpec contentType = 20
	recordAlert            contentType = 21
	recordHandshake        contentType = 22
	recordApplicationData  contentType = 23
)

// protocolVersion is the 2-byte wire version. DTLS uses the 1's-complement
// encoding: DTLS 1.2 is {254, 253} (RFC 6347 §4.1), DTLS 1.0 is {254, 255}
// (the version field of a pre-cookie ClientHello may legitimately be either).
var (
	versionDTLS12 = [2]byte{254, 253}
	versionDTLS10 = [2]byte{254, 255}
)

// recordHeaderLen is the fixed DTLS record header size: type(1) + version(2) +
// epoch(2) + sequence_number(6) + length(2).
const recordHeaderLen = 13

// maxRecordPayload bounds an inbound record's fragment length so a hostile length
// field cannot force a large allocation; it matches TLS's 2^14 plaintext limit
// plus AEAD expansion (explicit nonce + tag) and a margin (RFC 5246 §6.2.1).
const maxRecordPayload = 1 << 14

// errShortRecord is returned when a buffer is too short to hold the declared
// record. It is sentinel so the reader can distinguish a truncated trailing
// record from a malformed one.
var errShortRecord = errors.New("rist: dtls: short record")

// record is one parsed DTLS record. fragment aliases the source datagram on
// decode (the caller owns the datagram for the record's lifetime).
type record struct {
	typ      contentType
	version  [2]byte
	epoch    uint16
	seq      uint64 // 48-bit sequence number
	fragment []byte
}

// seqAndEpoch packs the 16-bit epoch and 48-bit sequence number into the 64-bit
// value used as the AEAD nonce's record-sequence input and the AAD seq_num
// (RFC 6347 §4.1.2.1): (epoch << 48) | sequence_number.
func seqAndEpoch(epoch uint16, seq uint64) uint64 {
	return uint64(epoch)<<48 | (seq & 0x0000FFFFFFFFFFFF)
}

// marshal appends the record (header + fragment) to dst and returns it.
func (r record) marshal(dst []byte) []byte {
	dst = append(dst, byte(r.typ))
	dst = append(dst, r.version[0], r.version[1])
	dst = binary.BigEndian.AppendUint16(dst, r.epoch)
	dst = appendUint48(dst, r.seq)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(r.fragment)))
	return append(dst, r.fragment...)
}

// parseRecord decodes the record at the front of b, returning it and the number
// of bytes consumed (header + fragment). It never panics on arbitrary input. A
// declared length that overruns b returns errShortRecord so a datagram with a
// truncated trailing record can be handled distinctly from a corrupt one.
func parseRecord(b []byte) (record, int, error) {
	if len(b) < recordHeaderLen {
		return record{}, 0, errShortRecord
	}
	length := int(binary.BigEndian.Uint16(b[11:13]))
	if length > maxRecordPayload {
		return record{}, 0, fmt.Errorf("rist: dtls: record length %d exceeds %d", length, maxRecordPayload)
	}
	end := recordHeaderLen + length
	if len(b) < end {
		return record{}, 0, errShortRecord
	}
	r := record{
		typ:      contentType(b[0]),
		version:  [2]byte{b[1], b[2]},
		epoch:    binary.BigEndian.Uint16(b[3:5]),
		seq:      uint48(b[5:11]),
		fragment: b[recordHeaderLen:end],
	}
	return r, end, nil
}

// splitRecords decodes every record packed into one datagram (DTLS permits
// several records per datagram, RFC 6347 §4.1.1). A trailing short record is
// dropped rather than failing the whole datagram; a record with an oversized
// length field fails. The returned records alias datagram.
func splitRecords(datagram []byte) ([]record, error) {
	var out []record
	for len(datagram) > 0 {
		r, n, err := parseRecord(datagram)
		if errors.Is(err, errShortRecord) {
			break // incomplete trailing record; ignore the remainder
		}
		if err != nil {
			return out, err
		}
		out = append(out, r)
		datagram = datagram[n:]
	}
	return out, nil
}

// appendUint48 appends the low 48 bits of v big-endian.
func appendUint48(dst []byte, v uint64) []byte {
	return append(dst,
		byte(v>>40), byte(v>>32), byte(v>>24),
		byte(v>>16), byte(v>>8), byte(v))
}

// uint48 reads a 48-bit big-endian integer from b (which must be >= 6 bytes).
func uint48(b []byte) uint64 {
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}
