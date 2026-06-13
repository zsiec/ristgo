package adv

import "testing"

// Encode/decode benchmarks: Build into a reused buffer is the per-packet
// Advanced-Profile framing hot path; the -benchmem numbers must show 0
// allocs/op (also gated by TestBuildZeroAllocs).

func BenchmarkBuildBasic(b *testing.B) {
	params := Params{
		Seq:       0x12345678,
		Timestamp: 1000000,
		SSRC:      0xAABBCC00,
		EncType:   TypeDirect,
		FirstFrag: true,
		LastFrag:  true,
	}
	payload := make([]byte, 1316)
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = Build(buf[:0], params, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = buf
}

func BenchmarkBuildAESCTR(b *testing.B) {
	params := Params{
		Seq:       1,
		EncType:   TypeDirect,
		PSKMode:   PSKAESCTR,
		FirstFrag: true,
		LastFrag:  true,
		PSKNonce:  []byte{1, 2, 3, 4},
		PSKIV:     []byte{5, 6, 7, 8},
	}
	payload := make([]byte, 1316)
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = Build(buf[:0], params, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = buf
}

func BenchmarkParseBasic(b *testing.B) {
	params := Params{
		Seq:       0x12345678,
		Timestamp: 1000000,
		SSRC:      0xAABBCC00,
		EncType:   TypeDirect,
		FirstFrag: true,
		LastFrag:  true,
	}
	wire, err := Build(nil, params, make([]byte, 1316))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(wire); err != nil {
			b.Fatal(err)
		}
	}
}

// TestBuildZeroAllocs gates the hot-path encoder at 0 allocs/op when writing
// into a pre-sized, reused buffer. Build never allocates the Params (FlowID/PFD
// are stack values here), so the only potential allocation is buffer growth,
// which the pre-sized buffer avoids.
func TestBuildZeroAllocs(t *testing.T) {
	params := Params{
		Seq:       0x12345678,
		Timestamp: 1000000,
		SSRC:      0xAABBCC00,
		EncType:   TypeDirect,
		PSKMode:   PSKAESCTR,
		FirstFrag: true,
		LastFrag:  true,
		PSKNonce:  []byte{1, 2, 3, 4},
		PSKIV:     []byte{5, 6, 7, 8},
	}
	payload := make([]byte, 1316)
	buf := make([]byte, 0, 2048)
	if n := testing.AllocsPerRun(100, func() {
		buf, _ = Build(buf[:0], params, payload)
	}); n != 0 {
		t.Fatalf("Build: %v allocs/op, want 0", n)
	}
}

// TestParseZeroAllocs gates Parse at 0 allocs/op (zero-copy decode).
func TestParseZeroAllocs(t *testing.T) {
	params := Params{Seq: 1, EncType: TypeDirect, FirstFrag: true, LastFrag: true}
	wire, err := Build(nil, params, make([]byte, 1316))
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() {
		_, _ = Parse(wire)
	}); n != 0 {
		t.Fatalf("Parse: %v allocs/op, want 0", n)
	}
}
