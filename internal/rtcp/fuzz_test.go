package rtcp

import (
	"bytes"
	"reflect"
	"testing"
)

// fuzzSeeds returns one valid encoding of every packet type plus a few
// deliberately awkward inputs, seeding both fuzz targets.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{0x80},
		{0x80, 0xC8, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF},
	}
	for _, tt := range goldenVectors {
		seeds = append(seeds, tt.pkt.AppendTo(nil))
	}
	// A full receiver compound.
	var compound []byte
	compound = EmptyReceiverReport{SSRC: 1}.AppendTo(compound)
	compound = SDES{SSRC: 1, CNAME: "fuzz"}.AppendTo(compound)
	compound = ExtSeq{SSRC: 1, SeqHigh: 7}.AppendTo(compound)
	compound = RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{Start: 65535, Extra: 3}}}.AppendTo(compound)
	compound = EchoRequest{SSRC: 1, Timestamp: 99}.AppendTo(compound)
	return append(seeds, compound)
}

// FuzzParse feeds arbitrary bytes to the single-packet parser: it must
// never panic, and anything it accepts must re-encode byte-stably.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		pkt, n, err := Parse(b)
		if err != nil {
			if pkt != nil || n != 0 {
				t.Fatalf("Parse returned (%v, %d) alongside error %v", pkt, n, err)
			}
			return
		}
		if n < headerSize || n > len(b) || n%4 != 0 {
			t.Fatalf("Parse consumed %d of %d bytes", n, len(b))
		}

		// First-generation encode: must itself parse, to an equal value,
		// and the second-generation encode must be byte-identical
		// (encoders normalize, so enc1 may differ from the raw input —
		// but only once).
		enc1 := pkt.AppendTo(nil)
		if len(enc1) != pkt.MarshalSize() {
			t.Fatalf("len(AppendTo) = %d, MarshalSize = %d", len(enc1), pkt.MarshalSize())
		}
		pkt2, n2, err := Parse(enc1)
		if err != nil {
			t.Fatalf("re-Parse of %x failed: %v (from %#v)", enc1, err, pkt)
		}
		if n2 != len(enc1) {
			t.Fatalf("re-Parse consumed %d of %d", n2, len(enc1))
		}
		if !reflect.DeepEqual(pkt2, pkt) {
			t.Fatalf("re-Parse = %#v, want %#v", pkt2, pkt)
		}
		if enc2 := pkt2.AppendTo(nil); !bytes.Equal(enc2, enc1) {
			t.Fatalf("re-encode unstable:\nenc1 %x\nenc2 %x", enc1, enc2)
		}

		// Raw packets must preserve input bytes exactly.
		if raw, ok := pkt.(Raw); ok && !bytes.Equal(raw, b[:n]) {
			t.Fatalf("Raw = %x, want input prefix %x", []byte(raw), b[:n])
		}
	})
}

// FuzzParseCompound feeds arbitrary datagrams to the compound parser: no
// panics, and every parsed packet obeys the same stability contract.
func FuzzParseCompound(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		pkts, err := ParseCompound(b)
		if err != nil {
			if pkts != nil {
				t.Fatalf("ParseCompound returned packets alongside error %v", err)
			}
			return
		}
		if len(pkts) == 0 {
			t.Fatal("ParseCompound returned no packets and no error")
		}
		for i, pkt := range pkts {
			enc1 := pkt.AppendTo(nil)
			pkt2, _, err := Parse(enc1)
			if err != nil {
				t.Fatalf("packet %d: re-Parse failed: %v", i, err)
			}
			if !reflect.DeepEqual(pkt2, pkt) {
				t.Fatalf("packet %d: re-Parse = %#v, want %#v", i, pkt2, pkt)
			}
			if enc2 := pkt2.AppendTo(nil); !bytes.Equal(enc2, enc1) {
				t.Fatalf("packet %d: re-encode unstable", i)
			}
		}
	})
}

// FuzzDecodeNACKSeam drives the seq-list seam from raw fuzz input shaped
// into a sorted circular sequence set: the encode->decode identity must
// hold for both encodings.
func FuzzDecodeNACKSeam(f *testing.F) {
	f.Add(uint16(0), []byte{1, 2, 3})
	f.Add(uint16(65530), []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	f.Add(uint16(65535), []byte{0})
	f.Add(uint16(100), []byte{16, 17, 1, 255})
	f.Fuzz(func(t *testing.T, start uint16, gaps []byte) {
		if len(gaps) > 4096 {
			gaps = gaps[:4096]
		}
		missing := []uint32{uint32(start)}
		cur, span := start, 0
		for _, g := range gaps {
			gap := int(g)%512 + 1
			if span+gap >= 1<<16 {
				break
			}
			span += gap
			cur += uint16(gap)
			missing = append(missing, uint32(cur))
		}

		var got []uint32
		for _, p := range EncodeRangeNACK(1, 2, missing) {
			got = p.AppendMissingSeqs(got)
		}
		if !reflect.DeepEqual(got, missing) {
			t.Fatalf("range seam: got %v, want %v", got, missing)
		}

		got = got[:0]
		for _, p := range EncodeBitmaskNACK(1, 2, missing) {
			got = p.AppendMissingSeqs(got)
		}
		if !reflect.DeepEqual(got, missing) {
			t.Fatalf("bitmask seam: got %v, want %v", got, missing)
		}
	})
}
