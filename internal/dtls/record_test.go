package dtls

import (
	"bytes"
	"errors"
	"testing"
)

func TestRecordRoundTrip(t *testing.T) {
	r := record{
		typ:      recordHandshake,
		version:  versionDTLS12,
		epoch:    1,
		seq:      0x0000FFFFFFFFFFFF, // max 48-bit
		fragment: []byte("hello dtls"),
	}
	enc := r.marshal(nil)
	if len(enc) != recordHeaderLen+len(r.fragment) {
		t.Fatalf("marshalled length = %d, want %d", len(enc), recordHeaderLen+len(r.fragment))
	}

	got, n, err := parseRecord(enc)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if n != len(enc) {
		t.Errorf("consumed %d, want %d", n, len(enc))
	}
	if got.typ != r.typ || got.version != r.version || got.epoch != r.epoch || got.seq != r.seq {
		t.Errorf("header mismatch: got %+v want %+v", got, r)
	}
	if !bytes.Equal(got.fragment, r.fragment) {
		t.Errorf("fragment = %q, want %q", got.fragment, r.fragment)
	}
}

func TestParseRecordShort(t *testing.T) {
	// Fewer than header bytes.
	if _, _, err := parseRecord([]byte{22, 254, 253}); !errors.Is(err, errShortRecord) {
		t.Errorf("short header: err = %v, want errShortRecord", err)
	}
	// Header declares 10 bytes of fragment but none follow.
	hdr := record{typ: recordApplicationData, version: versionDTLS12, fragment: make([]byte, 10)}.marshal(nil)
	if _, _, err := parseRecord(hdr[:recordHeaderLen]); !errors.Is(err, errShortRecord) {
		t.Errorf("short fragment: err = %v, want errShortRecord", err)
	}
}

func TestParseRecordOversize(t *testing.T) {
	b := make([]byte, recordHeaderLen)
	b[0] = byte(recordApplicationData)
	b[1], b[2] = 254, 253
	b[11], b[12] = 0xFF, 0xFF // length 65535 > maxRecordPayload
	if _, _, err := parseRecord(b); err == nil || errors.Is(err, errShortRecord) {
		t.Errorf("oversize length: err = %v, want a non-short error", err)
	}
}

func TestSplitRecords(t *testing.T) {
	r1 := record{typ: recordHandshake, version: versionDTLS12, epoch: 0, seq: 1, fragment: []byte("aaa")}
	r2 := record{typ: recordApplicationData, version: versionDTLS12, epoch: 1, seq: 2, fragment: []byte("bbbb")}
	datagram := r2.marshal(r1.marshal(nil))

	got, err := splitRecords(datagram)
	if err != nil {
		t.Fatalf("splitRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if !bytes.Equal(got[0].fragment, r1.fragment) || !bytes.Equal(got[1].fragment, r2.fragment) {
		t.Errorf("fragments = %q,%q want %q,%q", got[0].fragment, got[1].fragment, r1.fragment, r2.fragment)
	}

	// A truncated trailing record is dropped, not fatal.
	truncated := append(datagram, 22, 254, 253) // 3 dangling bytes
	got, err = splitRecords(truncated)
	if err != nil {
		t.Fatalf("splitRecords truncated: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("truncated: got %d records, want 2", len(got))
	}
}

func TestSeqAndEpoch(t *testing.T) {
	if v := seqAndEpoch(1, 0xFFFFFFFFFFFF); v != 0x0001FFFFFFFFFFFF {
		t.Errorf("seqAndEpoch = %x, want 0001FFFFFFFFFFFF", v)
	}
	// The 48-bit sequence is masked, never bleeding into the epoch bits.
	if v := seqAndEpoch(0, 0xFFFFFFFFFFFFFF); v != 0x0000FFFFFFFFFFFF {
		t.Errorf("seqAndEpoch over-wide seq = %x, want 0000FFFFFFFFFFFF", v)
	}
}
