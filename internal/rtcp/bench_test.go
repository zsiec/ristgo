package rtcp

import "testing"

// Encode benchmarks: AppendTo into a reused buffer is the periodic-RTCP and
// NACK hot path; the -benchmem numbers must show 0 allocs/op (also gated by
// TestEncodeZeroAllocs).

func benchAppendTo(b *testing.B, pkt Packet) {
	b.Helper()
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = pkt.AppendTo(buf[:0])
	}
	_ = buf
}

func BenchmarkSenderReportAppendTo(b *testing.B) {
	benchAppendTo(b, SenderReport{SSRC: 1, NTP: 0x83AA7E80_40000000, RTPTime: 90000, PacketCount: 7, OctetCount: 9000})
}

func BenchmarkEmptyReceiverReportAppendTo(b *testing.B) {
	benchAppendTo(b, EmptyReceiverReport{SSRC: 1})
}

func BenchmarkSDESAppendTo(b *testing.B) {
	benchAppendTo(b, SDES{SSRC: 1, CNAME: "ristgo-bench"})
}

func BenchmarkRangeNACKAppendTo(b *testing.B) {
	benchAppendTo(b, RangeNACK{MediaSSRC: 1, Ranges: []NackRange{
		{0, 3}, {100, 0}, {500, 16}, {65535, 1},
	}})
}

func BenchmarkBitmaskNACKAppendTo(b *testing.B) {
	benchAppendTo(b, BitmaskNACK{SenderSSRC: 1, MediaSSRC: 2, FCIs: []NackPair{
		{0, 0xFFFF}, {100, 0}, {500, 0x8001}, {65535, 1},
	}})
}

func BenchmarkEchoRequestAppendTo(b *testing.B) {
	benchAppendTo(b, EchoRequest{SSRC: 1, Timestamp: 0x0102030405060708})
}

func BenchmarkExtSeqAppendTo(b *testing.B) {
	benchAppendTo(b, ExtSeq{SSRC: 1, SeqHigh: 2})
}

// BenchmarkBuildCompound measures the full receiver NACK compound (empty RR
// + SDES + range NACK), the most frequent transmit path under loss.
func BenchmarkBuildCompound(b *testing.B) {
	pkts := []Packet{
		EmptyReceiverReport{SSRC: 1},
		SDES{SSRC: 1, CNAME: "ristgo-bench"},
		RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{100, 4}, {300, 0}}},
	}
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = BuildCompound(buf[:0], pkts)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = buf
}

// BenchmarkParseCompound measures the receive path for the same compound.
func BenchmarkParseCompound(b *testing.B) {
	var datagram []byte
	datagram = EmptyReceiverReport{SSRC: 1}.AppendTo(datagram)
	datagram = SDES{SSRC: 1, CNAME: "ristgo-bench"}.AppendTo(datagram)
	datagram = RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{100, 4}, {300, 0}}}.AppendTo(datagram)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseCompound(datagram); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncodeRangeNACKSeam measures the seq-list seam for a burst loss
// pattern (mixed runs and singles).
func BenchmarkEncodeRangeNACKSeam(b *testing.B) {
	missing := make([]uint32, 0, 64)
	for i := 0; i < 8; i++ {
		missing = append(missing, seqSpan(i*1000, 5)...)
		missing = append(missing, uint32(uint16(i*1000+600)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if pkts := EncodeRangeNACK(1, 2, missing); len(pkts) == 0 {
			b.Fatal("no packets")
		}
	}
}
