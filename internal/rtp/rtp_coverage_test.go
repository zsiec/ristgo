package rtp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// validHeader12 is a minimal valid 12-byte header used as a template by the
// truncation tests: V=2, PT=33, seq 1, ts 2, ssrc 4.
var validHeader12 = []byte{0x80, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4}

func TestHeaderUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr error
	}{
		{"nil", nil, ErrHeaderTooShort},
		{"empty", []byte{}, ErrHeaderTooShort},
		{"one-byte", []byte{0x80}, ErrHeaderTooShort},
		{"eleven-bytes", validHeader12[:11], ErrHeaderTooShort},
		{
			// CC=2 announces 8 CSRC bytes but only 4 are present.
			"csrc-truncated",
			append([]byte{0x82, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4}, 0, 0, 0, 9),
			ErrHeaderTooShort,
		},
		{
			// CC=15 (byte0 0x8F) with only the fixed header present.
			"max-csrc-truncated",
			[]byte{0x8F, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4},
			ErrHeaderTooShort,
		},
		{
			// X=1 (byte0 0x90) but no extension header at all.
			"extension-header-missing",
			[]byte{0x90, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4},
			ErrExtensionTooShort,
		},
		{
			// X=1, only 2 of the 4 extension header bytes present.
			"extension-header-truncated",
			append([]byte{0x90, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4}, 0x52, 0x49),
			ErrExtensionTooShort,
		},
		{
			// X=1, extension announces 2 words (8 bytes) but carries 4.
			"extension-payload-truncated",
			append([]byte{0x90, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4},
				0x52, 0x49, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD),
			ErrExtensionTooShort,
		},
		{
			// X=1, extension announces the maximum 0xFFFF words.
			"extension-length-max-truncated",
			append([]byte{0x90, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4},
				0x52, 0x49, 0xFF, 0xFF),
			ErrExtensionTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h Header
			if _, err := h.Unmarshal(tc.wire); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Unmarshal(%x) error = %v, want %v", tc.wire, err, tc.wantErr)
			}
			var p Packet
			if err := p.Unmarshal(tc.wire); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Packet.Unmarshal(%x) error = %v, want %v", tc.wire, err, tc.wantErr)
			}
		})
	}
}

func TestHeaderUnmarshalVersionBits(t *testing.T) {
	// The 2-bit V field is carried as-is; Unmarshal does not reject
	// non-2 versions (matching pion and librist, which never check it).
	for version := uint8(0); version <= 3; version++ {
		wire := append([]byte{}, validHeader12...)
		wire[0] = version<<6 | wire[0]&0x3F
		var h Header
		if _, err := h.Unmarshal(wire); err != nil {
			t.Fatalf("Unmarshal(version %d): %v", version, err)
		}
		if h.Version != version {
			t.Fatalf("Version = %d, want %d", h.Version, version)
		}
	}
}

func TestHeaderMarshalErrors(t *testing.T) {
	valid := Header{Version: 2, SequenceNumber: 1}

	tests := []struct {
		name    string
		hdr     Header
		buf     int // destination buffer length
		wantErr error
	}{
		{"version-4", Header{Version: 4}, 64, ErrInvalidVersion},
		{"version-255", Header{Version: 255}, 64, ErrInvalidVersion},
		{
			"sixteen-csrcs",
			Header{Version: 2, CSRC: make([]uint32, 16)},
			128,
			ErrTooManyCSRC,
		},
		{
			"extension-unaligned",
			Header{Version: 2, Extension: true, ExtensionPayload: []byte{1, 2, 3}},
			64,
			ErrExtensionNotAligned,
		},
		{
			"extension-too-long",
			Header{Version: 2, Extension: true, ExtensionPayload: make([]byte, 4*0x10000)},
			4*0x10000 + 64,
			ErrExtensionTooLong,
		},
		{"buffer-empty", valid, 0, ErrShortBuffer},
		{"buffer-eleven", valid, 11, ErrShortBuffer},
		{
			"buffer-misses-csrc",
			Header{Version: 2, CSRC: []uint32{1, 2}},
			12 + 4, // room for one CSRC, not two
			ErrShortBuffer,
		},
		{
			"buffer-misses-extension",
			Header{Version: 2, Extension: true, ExtensionPayload: []byte{1, 2, 3, 4}},
			12 + 4, // room for the ext header, not its payload
			ErrShortBuffer,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := tc.hdr.MarshalTo(make([]byte, tc.buf))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("MarshalTo error = %v, want %v", err, tc.wantErr)
			}
			if n != 0 {
				t.Fatalf("MarshalTo n = %d on error, want 0", n)
			}

			// AppendTo must fail identically and leave buf unchanged.
			prefix := []byte{0xAB}
			out, err := tc.hdr.AppendTo(prefix)
			if tc.wantErr == ErrShortBuffer {
				// AppendTo sizes the buffer itself; short-buffer
				// cases cannot occur through it.
				if err != nil {
					t.Fatalf("AppendTo: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("AppendTo error = %v, want %v", err, tc.wantErr)
			}
			if len(out) != 1 || out[0] != 0xAB {
				t.Fatalf("AppendTo on error returned %x, want original prefix", out)
			}
		})
	}
}

func TestPacketMarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		pkt     Packet
		buf     int
		wantErr error
	}{
		{
			"padding-bit-without-size",
			Packet{Header: Header{Version: 2, Padding: true}},
			64,
			ErrInvalidPadding,
		},
		{
			"padding-size-without-bit",
			Packet{Header: Header{Version: 2}, PaddingSize: 4},
			64,
			ErrInvalidPadding,
		},
		{
			"buffer-misses-payload",
			Packet{Header: Header{Version: 2}, Payload: []byte{1, 2, 3, 4}},
			12 + 2,
			ErrShortBuffer,
		},
		{
			"buffer-misses-padding",
			Packet{
				Header:      Header{Version: 2, Padding: true},
				Payload:     []byte{1},
				PaddingSize: 4,
			},
			12 + 1 + 2,
			ErrShortBuffer,
		},
		{
			"header-error-propagates",
			Packet{Header: Header{Version: 9}},
			64,
			ErrInvalidVersion,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := tc.pkt.MarshalTo(make([]byte, tc.buf))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("MarshalTo error = %v, want %v", err, tc.wantErr)
			}
			if n != 0 {
				t.Fatalf("MarshalTo n = %d on error, want 0", n)
			}

			if tc.wantErr != ErrShortBuffer {
				out, err := tc.pkt.AppendTo([]byte{0xCD})
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("AppendTo error = %v, want %v", err, tc.wantErr)
				}
				if len(out) != 1 || out[0] != 0xCD {
					t.Fatalf("AppendTo on error returned %x, want original prefix", out)
				}
			}
		})
	}
}

func TestPacketMarshalPaddingZeroFill(t *testing.T) {
	// Padding filler bytes must be written as zeros even into a dirty
	// buffer (decode discards wire filler; encode regenerates zeros).
	p := Packet{
		Header:      Header{Version: 2, Padding: true},
		Payload:     []byte{0xEE},
		PaddingSize: 4,
	}
	buf := bytes.Repeat([]byte{0xFF}, p.MarshalSize())
	n, err := p.MarshalTo(buf)
	if err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x04}
	if !bytes.Equal(buf[n-4:n], want) {
		t.Fatalf("padding bytes = %x, want %x", buf[n-4:n], want)
	}
}

func TestHeaderUnmarshalReuse(t *testing.T) {
	// A Header reused across Unmarshal calls must not leak state from
	// the previous packet.
	loaded := goldenPackets[2].wire // csrc-extension-padding
	minimal := goldenPackets[0].wire

	var h Header
	if _, err := h.Unmarshal(loaded); err != nil {
		t.Fatalf("Unmarshal(loaded): %v", err)
	}
	if len(h.CSRC) != 2 || !h.Extension || h.ExtensionProfile != ExtensionProfileRIST {
		t.Fatalf("loaded decode wrong: %+v", h)
	}
	csrcPtr := &h.CSRC[0]

	if _, err := h.Unmarshal(minimal); err != nil {
		t.Fatalf("Unmarshal(minimal): %v", err)
	}
	if len(h.CSRC) != 0 || h.Extension || h.ExtensionProfile != 0 || h.ExtensionPayload != nil {
		t.Fatalf("stale state after reuse: %+v", h)
	}

	// Decoding a 1-CSRC packet next must reuse the existing capacity.
	oneCSRC := append([]byte{0x81, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4}, 0, 0, 0, 9)
	if _, err := h.Unmarshal(oneCSRC); err != nil {
		t.Fatalf("Unmarshal(oneCSRC): %v", err)
	}
	if len(h.CSRC) != 1 || h.CSRC[0] != 9 {
		t.Fatalf("CSRC = %v, want [9]", h.CSRC)
	}
	if &h.CSRC[0] != csrcPtr {
		t.Fatalf("CSRC backing array not reused")
	}
}

func TestUnmarshalAliasesInput(t *testing.T) {
	// Decode is zero-copy: Payload and ExtensionPayload alias the input
	// buffer (a deliberate deviation from defensive copying; callers own
	// the lifetime of the receive buffer).
	wire := append([]byte{}, goldenPackets[2].wire...)
	var p Packet
	if err := p.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	wire[28] = 0x77 // first payload byte (offset 28 in csrc-extension-padding)
	if p.Payload[0] != 0x77 {
		t.Fatalf("Payload does not alias input buffer")
	}
	wire[24] = 0x66 // first extension payload byte
	if p.ExtensionPayload[0] != 0x66 {
		t.Fatalf("ExtensionPayload does not alias input buffer")
	}
}

func TestErrorStringsHaveRistPrefix(t *testing.T) {
	for _, err := range []error{
		ErrHeaderTooShort,
		ErrExtensionTooShort,
		ErrPacketTooShort,
		ErrInvalidPadding,
		ErrShortBuffer,
		ErrInvalidVersion,
		ErrTooManyCSRC,
		ErrExtensionNotAligned,
		ErrExtensionTooLong,
	} {
		if !strings.HasPrefix(err.Error(), "rist: ") {
			t.Errorf("error %q lacks \"rist: \" prefix", err)
		}
	}
}

func TestAppendToGrowth(t *testing.T) {
	pkt := goldenPackets[0].pkt

	// Sufficient capacity: no reallocation, prefix preserved.
	buf := make([]byte, 1, 1+pkt.MarshalSize())
	buf[0] = 0x42
	out, err := pkt.AppendTo(buf)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	if &out[0] != &buf[0] {
		t.Fatalf("AppendTo reallocated despite sufficient capacity")
	}
	if out[0] != 0x42 || !bytes.Equal(out[1:], goldenPackets[0].wire) {
		t.Fatalf("AppendTo = %x, want 42%x", out, goldenPackets[0].wire)
	}

	// Insufficient capacity: reallocates, contents still correct.
	out2, err := pkt.AppendTo(out)
	if err != nil {
		t.Fatalf("AppendTo (grow): %v", err)
	}
	if !bytes.Equal(out2[len(out):], goldenPackets[0].wire) {
		t.Fatalf("AppendTo after growth = %x", out2)
	}
}
