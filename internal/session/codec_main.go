package session

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/gre"
	"github.com/zsiec/ristgo/internal/npd"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/rtp"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file is the Main-profile (VSF TR-06-2) codec strategy: the GRE-tunnelled
// analog of the Simple-profile codec in codec.go. It translates between the
// flow core's normalized wire.MediaPacket / wire.Feedback values and
// Main-profile GRE datagrams, reusing the Simple codec's RTP/RTCP encode,
// decode, and sequence/timestamp widening helpers (encodeMedia, encodeFeedback,
// mediaDecoder, widenSeq/widenTicks/widenSeqAtMost) and wrapping their bytes in
// the Main-profile framing.
//
// # Single-port multiplex
//
// Main profile carries media AND compound RTCP over one UDP port, both
// GRE-tunnelled (RIST_GRE_PROTOCOL_TYPE_REDUCED). Every
// outbound datagram is:
//
//	GRE base header (seq always; +nonce when encrypting)
//	  | reduced-overhead header (virt src/dst port)
//	  | inner RTP packet (media)  OR  compound RTCP (feedback)
//
// When PSK is enabled the reduced header and the inner RTP/RTCP+payload are
// encrypted together as one AES-CTR region beginning immediately after the GRE
// sequence number; the GRE base header, nonce, and sequence
// stay in cleartext. The IV is the 32-bit GRE sequence (crypto.BuildIV).
//
// # GRE sequence number
//
// The GRE sequence is the codec's own monotonically increasing per-datagram
// counter — the AES IV high bytes and the GRE-layer sequence, NOT the media RTP
// sequence. It increments for every datagram sent, media or RTCP.
//
// # Receive demux (the key rule)
//
// After gre.Parse, decrypting if a key is present, and stripping the 4-byte
// reduced header, the codec peeks the second byte of the inner packet (the
// RTP/RTCP payload-type byte). With pt = byte & 0x7f, 72 <= pt <= 77 means RTCP
// (PT 200-205) and routes to compound-RTCP feedback decode; anything else is
// RTP media. The reduced-header port is not consulted
// for this — the PT byte is authoritative, matching libRIST.
//
// At the default and minimum GRE version (1) the GRE protocol type is
// RIST_GRE_PROTOCOL_TYPE_REDUCED (0x88B6), written directly with no VSF wrapper.
// This codec always uses version 1.

// rtcpPTByteLow is the inner-packet byte index whose low 7 bits hold the
// payload type for both RTP (marker+PT) and RTCP (version+count / PT depending
// on layout). For the demux the relevant byte is the SECOND octet of the inner
// packet: for RTP it is marker|payload_type, for RTCP it is the packet-type
// octet (rtp->payload_type read from the same offset).
const rtcpPTByteLow = 1

// rtcpPTMin and rtcpPTMax bound the RTCP payload-type range after masking the
// marker bit: PT 200-205 minus 128 is the conflict-avoidance window 72-77.
// An inner second-byte whose low 7 bits fall in this
// range is decoded as compound RTCP; anything else is RTP media.
const (
	rtcpPTMin = 72
	rtcpPTMax = 77
)

// npdExtPayloadLen is the length of the RIST NPD RTP-extension payload — the
// bytes after the 4-byte RFC 3550 extension header (flags, npd_bits, seq_ext).
// The RIST extension is exactly one 32-bit word (length=1), so the payload is
// four bytes; any other length is not the canonical NPD extension and is
// ignored on decode (matching libRIST's be16toh(length)==1 gate).
const npdExtPayloadLen = 4

// hBitKeySize maps the GRE H bit (KeySize256) to the AES key size in bits the
// receiver derives with: 256 when set, 128 when clear.
func hBitKeySize(keySize256 bool) int {
	if keySize256 {
		return crypto.KeySize256
	}
	return crypto.KeySize128
}

// mainCodec is the stateful Main-profile codec for one direction of a flow. It
// is the analog of the Simple codec's loose function set, gathered into a
// struct because the Main profile carries direction-scoped state: the GRE
// sequence counter, the PSK send Key and receive Decryptor, the media decoder's
// widening references, and the reduced-header virtual ports. It is NOT safe for
// concurrent use; the host serializes a single send/receive path onto it.
type mainCodec struct {
	// sendKey is the PSK encryptor, or nil when encryption is disabled. When
	// non-nil, every datagram's reduced header and inner packet are encrypted
	// together and the GRE nonce/key bit are emitted.
	sendKey *crypto.Key

	// recvKey is the PSK decryptor, or nil when encryption is disabled. It
	// re-derives its AES key whenever the inbound GRE nonce changes.
	recvKey *crypto.Decryptor

	// keySize256 selects the GRE H bit for outbound encrypted datagrams: true
	// for a 256-bit AES key, false for 128-bit. Meaningful only when sendKey is
	// non-nil; the host configures it to match the send Key's key size
	// (crypto.Key does not expose its key size).
	//
	// The receive path honors the INBOUND H bit independently: decodeMain calls
	// recvKey.SetKeyBits with the size the peer signalled before decrypting,
	// so a peer configured with a different aes-type still
	// interoperates. A secret mismatch still fails every decrypt; decodeMain
	// returns an error and the loop logs it.
	keySize256 bool

	// greSeq is the per-datagram GRE sequence counter (the AES IV high bytes
	// and the GRE-layer sequence). It increments for every datagram sent.
	greSeq uint32

	// dec reconstructs the 32-bit media sequence and NTP-64 source time from a
	// received RTP packet, exactly as the Simple codec's mediaDecoder does. The
	// media sequence always widens by rollover counting: libRIST carries only the
	// 16-bit RTP sequence on the Main path and never populates the NPD extension's
	// seq_ext (it reads seq_ext only in the Advanced profile; widens by
	// &UINT16_MAX), so trusting seq_ext would pin the high bits at zero
	// and break across the 16-bit wrap against a real libRIST peer.
	dec mediaDecoder

	// srcPort and dstPort are the reduced-overhead virtual ports
	// (DefaultVirtSrcPort 1971 / DefaultVirtDstPort 1968 by default).
	srcPort uint16
	dstPort uint16

	// npdEnabled selects null-packet deletion on the media encode path. When
	// set and a payload is a whole number of <=7 TS packets with at least one
	// null packet, the codec suppresses the nulls and attaches the RIST NPD
	// header extension (RTP X bit).
	npdEnabled bool

	// ssrc is the even base SSRC of this flow, and cname the SDES canonical
	// name, used to build outbound compound RTCP (mirroring the Simple codec's
	// encodeFeedback arguments).
	ssrc  uint32
	cname string

	// bitmask selects the NACK wire encoding for outbound feedback: false for
	// RIST range NACK (TR-06 default), true for RFC 4585 bitmask NACK.
	bitmask bool

	// Reusable encode scratch (loop-owned, single goroutine). The Main media
	// encode path is otherwise the only hot path that heap-allocates per packet
	// — unlike the 0-alloc Simple and Advanced-cleartext paths — so these
	// buffers let buildMediaRTP and frame reuse memory instead of passing nil.
	// They are distinct so none aliases another within one encode (rtpScratch
	// holds the inner RTP, npdScratch the null-suppressed payload, extScratch the
	// NPD extension bytes, regionScratch the cleartext AES region, ctScratch the
	// ciphertext); the final datagram is built in the caller's dst.
	rtpScratch    []byte
	npdScratch    []byte
	extScratch    []byte
	regionScratch []byte
	ctScratch     []byte
}

// newMainCodec constructs a Main-profile codec. sendKey and recvKey may be nil
// to disable PSK encryption; when non-nil they must derive from the same
// passphrase and key size, and keySize256 must match the send key's size (true
// for 256-bit). srcPort/dstPort are the reduced-overhead virtual ports (pass
// gre.DefaultVirtSrcPort / gre.DefaultVirtDstPort for the defaults). npdEnabled
// turns on null-packet-deletion suppression on the media encode path. ssrc and
// cname seed the outbound compound RTCP; bitmask selects the NACK encoding.
func newMainCodec(sendKey *crypto.Key, recvKey *crypto.Decryptor, keySize256 bool, srcPort, dstPort uint16, npdEnabled bool, ssrc uint32, cname string, bitmask bool) *mainCodec {
	return &mainCodec{
		sendKey:    sendKey,
		recvKey:    recvKey,
		keySize256: keySize256,
		srcPort:    srcPort,
		dstPort:    dstPort,
		npdEnabled: npdEnabled,
		ssrc:       ssrc,
		cname:      cname,
		bitmask:    bitmask,
	}
}

// setSendKey installs (or replaces) the PSK encryptor used for outbound
// datagrams, with keySize256 selecting the GRE H bit. It is the re-key seam for
// the EAP-SRP use_key_as_passphrase mode: a Main session starts cleartext (no
// secret) and, on the SRP session key K becoming available, keys the send path
// from K. A nil key disables encryption. The host calls it on the loop goroutine
// (the codec's sole owner) before any media is sent, so no in-flight datagram
// straddles the change.
func (c *mainCodec) setSendKey(k *crypto.Key, keySize256 bool) {
	c.sendKey = k
	c.keySize256 = keySize256
}

// setRecvKey installs (or replaces) the PSK decryptor used for inbound
// datagrams. It is the receive-side counterpart of setSendKey (EAP-SRP
// use_key_as_passphrase re-key). A nil decryptor disables decryption.
func (c *mainCodec) setRecvKey(d *crypto.Decryptor) {
	c.recvKey = d
}

// hasSendKey reports whether the codec is currently keying its send path.
func (c *mainCodec) hasSendKey() bool { return c.sendKey != nil }

// encodeMainMedia encodes a normalized MediaPacket as one Main-profile data
// datagram, appending to dst and returning the extended slice. The RTP packet
// is built exactly as the Simple codec's encodeMedia does (even-base SSRC with
// the retransmit LSB toggle, 16-bit sequence, 90 kHz timestamp); when NPD is
// enabled and the payload is a whole number of <=7 TS packets containing at
// least one null packet, the nulls are suppressed and a RIST NPD header
// extension is prepended (RTP X bit set; the extension's seq_ext is 0, matching
// libRIST, which never carries a 32-bit media sequence on the Main path). The
// RTP bytes are then framed in the reduced-overhead header and GRE, encrypted
// under the PSK when one is configured.
//
// A retransmit and its original reconstruct to the same (Seq, SourceTime) on
// decode — the same dedup invariant the Simple codec preserves — because only
// the SSRC LSB differs on the wire.
func (c *mainCodec) encodeMainMedia(dst []byte, pkt wire.MediaPacket) ([]byte, error) {
	inner, err := c.buildMediaRTP(pkt)
	if err != nil {
		return dst, err
	}
	return c.frame(dst, inner)
}

// buildMediaRTP builds the inner RTP packet for a media datagram, applying NPD
// suppression and the RIST header extension when enabled and applicable. It
// returns a freshly built buffer (it does not alias pkt.Payload once NPD
// rewrites it). When NPD does not apply — disabled, ineligible payload, or no
// null packets present — the RTP packet is byte-identical to the Simple codec's
// encodeMedia output.
func (c *mainCodec) buildMediaRTP(pkt wire.MediaPacket) ([]byte, error) {
	if !c.npdEnabled {
		out, err := encodeMedia(c.rtpScratch[:0], pkt)
		c.rtpScratch = out
		return out, err
	}
	// Try to suppress null packets. Suppress copies through unchanged (and
	// reports suppressed==0) when the payload has no nulls; it errors when the
	// payload is not a whole number of <=7 TS packets. Either way, fall back
	// to a plain RTP packet — libRIST attaches the extension only when
	// suppress_null_packets returns > 0.
	reduced, npdBits, suppressed, err := npd.Suppress(c.npdScratch[:0], pkt.Payload)
	c.npdScratch = reduced
	if err != nil || suppressed == 0 {
		out, err := encodeMedia(c.rtpScratch[:0], pkt)
		c.rtpScratch = out
		return out, err
	}

	ssrc := pkt.SSRC
	if pkt.Retransmit {
		ssrc = rtp.MarkRetransmit(ssrc)
	}
	ext := npd.Ext{
		NPD:        true,
		Size204:    npdBits&npd.NPDSize204 != 0,
		NullBitmap: npdBits & npd.NullBitmapMask,
		// libRIST emits seq_ext=0 on the Simple/Main path (it reads seq_ext only
		// in the Advanced profile; widens the media sequence by 16-bit
		// rollover). Match it — the extension carries only NPD info,
		// and the receiver widens by rollover counting, not from seq_ext.
		SeqExt: 0,
	}
	p := rtp.Packet{
		Header: rtp.Header{
			Version:          rtp.Version,
			PayloadType:      rtp.PayloadTypeMPEGTS,
			SequenceNumber:   uint16(pkt.Seq),
			Timestamp:        rtpTSFromSource(pkt.SourceTime),
			SSRC:             ssrc,
			Extension:        true,
			ExtensionProfile: npd.Identifier,
			// The RTP layer writes the 4-byte RFC 3550 extension header
			// (profile + length) itself; ExtensionPayload is only the four
			// bytes after it: flags, npd_bits, seq_ext (npd.Ext minus its
			// identifier+length). appendExtPayload emits exactly those.
			ExtensionPayload: c.extScratch[:0],
		},
		Payload: reduced,
	}
	p.Header.ExtensionPayload = appendExtPayload(p.Header.ExtensionPayload, ext)
	c.extScratch = p.Header.ExtensionPayload
	out, err := p.AppendTo(c.rtpScratch[:0])
	c.rtpScratch = out
	return out, err
}

// appendExtPayload appends the four NPD extension-payload bytes (flags,
// npd_bits, seq_ext) — the body that follows the 4-byte RFC 3550 extension
// header — to dst and returns the extended slice. It is derived from
// npd.Ext.AppendTo (which emits the full 8-byte extension) by dropping the
// leading identifier+length, since the RTP encoder writes those itself.
func appendExtPayload(dst []byte, e npd.Ext) []byte {
	full := e.AppendTo(nil) // identifier(2) length(2) flags(1) npd_bits(1) seq_ext(2)
	return append(dst, full[4:]...)
}

// encodeMainFeedback encodes one Main-profile feedback datagram, appending to
// dst. It builds the compound RTCP exactly as the Simple codec's encodeFeedback
// does — the lead SR/RR, then SDES/CNAME, then NACKs, then echoes — but
// interleaves an EXTSEQ APP packet (PT 204, name "RIST", subtype 1) before any
// NACK whose missing sequences have non-zero high 16 bits, per TR-06-2 §8.4.
// The compound RTCP bytes are then framed in the reduced header and GRE,
// encrypted under the PSK when one is configured.
//
// lead is the mandatory first compound packet (an EmptyReceiverReport on the
// receiver, a SenderReport on the sender), matching encodeFeedback. bitmask
// selects the NACK encoding for this datagram, overriding the codec's default.
func (c *mainCodec) encodeMainFeedback(dst []byte, lead rtcp.Packet, fbs []wire.Feedback, bitmask bool) ([]byte, error) {
	compound, err := c.buildCompound(lead, fbs, bitmask)
	if err != nil {
		return dst, err
	}
	return c.frame(dst, compound)
}

// buildCompound assembles the compound RTCP bytes for a feedback datagram. It
// mirrors codec.go's encodeFeedback ordering (lead, SDES, NACKs, echoes) and
// adds EXTSEQ packets: a NACK whose Missing sequences span more than the low 16
// bits is split by upper half, and each group is preceded by its own EXTSEQ
// packet carrying that group's high 16 bits (TR-06-2 §8.4, exactly the pattern
// in rtcp.TestExtSeqWideningScenario).
func (c *mainCodec) buildCompound(lead rtcp.Packet, fbs []wire.Feedback, bitmask bool) ([]byte, error) {
	pkts := []rtcp.Packet{lead, rtcp.SDES{SSRC: c.ssrc, CNAME: c.cname}}
	var nacks, echoes []rtcp.Packet
	for _, fb := range fbs {
		switch f := fb.(type) {
		case wire.NackRequest:
			nacks = append(nacks, c.encodeNACK(f, bitmask)...)
		case wire.RttEchoRequest:
			// Originated request: stamp the local SSRC. (An inbound request
			// never reaches the encoder.)
			echoes = append(echoes, rtcp.EchoRequest{SSRC: c.ssrc, Timestamp: f.Timestamp})
		case wire.RttEchoResponse:
			// Echo the requester's SSRC (captured on decode), not our own: a
			// libRIST requester drops a response whose SSRC != its peer_ssrc.
			echoes = append(echoes, rtcp.EchoResponse{SSRC: f.SSRC, Timestamp: f.Timestamp, ProcessingDelay: f.ProcessingDelay})
		}
	}
	pkts = append(pkts, nacks...)
	pkts = append(pkts, echoes...)
	return rtcp.BuildCompound(nil, pkts)
}

// encodeNACK encodes one NackRequest into RTCP packets, prepending an EXTSEQ
// packet before each group of missing sequences that share an upper 16 bits.
// Sequences are visited in their given order; a new EXTSEQ is emitted whenever
// the high half changes (and always before the first group whose high half is
// non-zero, or before the first group when any group is non-zero). When every
// missing sequence has a zero upper half, no EXTSEQ is emitted and the output
// matches the Simple codec exactly.
func (c *mainCodec) encodeNACK(f wire.NackRequest, bitmask bool) []rtcp.Packet {
	if len(f.Missing) == 0 {
		return nil
	}
	// Determine whether any sequence needs EXTSEQ. When none do, emit the
	// plain Simple-codec encoding.
	needExt := false
	for _, s := range f.Missing {
		if s>>16 != 0 {
			needExt = true
			break
		}
	}
	if !needExt {
		return c.nackPackets(f.SSRC, f.Missing, bitmask)
	}

	// Split into runs of equal upper half, preserving order, and precede each
	// run with its EXTSEQ packet (TR-06-2 §8.4: entries with different upper
	// halves are separate NACK packets, each behind a new EXTSEQ).
	var out []rtcp.Packet
	i := 0
	for i < len(f.Missing) {
		hi := uint16(f.Missing[i] >> 16)
		j := i
		for j < len(f.Missing) && uint16(f.Missing[j]>>16) == hi {
			j++
		}
		out = append(out, rtcp.ExtSeq{SSRC: c.ssrc, SeqHigh: hi})
		out = append(out, c.nackPackets(f.SSRC, f.Missing[i:j], bitmask)...)
		i = j
	}
	return out
}

// nackPackets encodes a slice of missing sequences into range or bitmask NACK
// packets (the low 16 bits are used; the codec has already grouped by upper
// half). It is the per-group equivalent of the Simple codec's NACK branch.
func (c *mainCodec) nackPackets(mediaSSRC uint32, missing []uint32, bitmask bool) []rtcp.Packet {
	var out []rtcp.Packet
	if bitmask {
		// SenderSSRC is zero: TR-06-1 §5.3.2.1 has the RIST sender ignore it and
		// libRIST transmits zero, so match it on the wire.
		for _, p := range rtcp.EncodeBitmaskNACK(0, mediaSSRC, missing) {
			out = append(out, p)
		}
	} else {
		for _, p := range rtcp.EncodeRangeNACK(c.ssrc, mediaSSRC, missing) {
			out = append(out, p)
		}
	}
	return out
}

// frame wraps an inner packet (an RTP packet or a compound RTCP datagram) in
// the Main-profile reduced-overhead header and GRE header, encrypting the
// reduced header together with the inner packet under the PSK when one is
// configured, and appends the result to dst. It increments the GRE sequence
// counter once per call.
//
// The layout matches libRIST: the GRE base header (with the sequence always
// present, and the key/nonce present only when encrypting) is cleartext; the
// AES-CTR region — when encrypting — begins immediately after the GRE sequence
// and covers the reduced header and inner packet together.
func (c *mainCodec) frame(dst, inner []byte) ([]byte, error) {
	seq := c.greSeq
	c.greSeq++

	hdr := gre.Header{
		Version:  gre.VersionMin, // version 1: REDUCED written directly
		HasSeq:   true,
		ProtType: gre.ProtoReduced,
		Seq:      seq,
	}
	reduced := gre.ReducedHeader{SrcPort: c.srcPort, DstPort: c.dstPort}

	if c.sendKey == nil {
		// Cleartext: GRE base + reduced + inner, no key bit.
		out, err := hdr.AppendTo(dst)
		if err != nil {
			return dst, err
		}
		out = reduced.AppendTo(out)
		return append(out, inner...), nil
	}

	// Encrypted: the AES-CTR region is the reduced header followed by the
	// inner packet, encrypted as one block under the GRE sequence's IV. Build
	// the cleartext region in a reused scratch buffer, then encrypt it (into a
	// second reused buffer) after the GRE header. The key may rotate on Encrypt,
	// so read the nonce afterwards.
	region := reduced.AppendTo(c.regionScratch[:0])
	region = append(region, inner...)
	c.regionScratch = region

	ct, err := c.sendKey.Encrypt(seq, c.ctScratch[:0], region)
	if err != nil {
		return dst, err
	}
	c.ctScratch = ct
	hdr.HasKey = true
	hdr.KeySize256 = c.keySize256
	hdr.Nonce = c.sendKey.Nonce()

	out, err := hdr.AppendTo(dst)
	if err != nil {
		return dst, err
	}
	return append(out, ct...), nil
}

// controlKind identifies a decoded GRE control message peeked by peekControl.
type controlKind uint8

const (
	controlNone      controlKind = iota // not a control datagram
	controlKeepalive                    // a GRE keepalive (caps + MAC)
	controlBufferNeg                    // a VSF buffer-negotiation message
)

// frameControl frames a GRE control body (a keepalive or buffer-negotiation
// message) at the given GRE version: version 1 writes the protocol type directly
// (ProtoKeepalive); version >= 2 wraps it in the VSF ethertype + 4-byte VSF
// proto. The body is encrypted under the PSK when one is configured (matching
// libRIST's send_data, which runs keepalives through the encrypted path). It
// increments the shared GRE sequence counter once.
func (c *mainCodec) frameControl(dst, body []byte, version uint8, proto, vsfSubtype uint16) ([]byte, error) {
	seq := c.greSeq
	c.greSeq++
	hdr := gre.Header{Version: version, HasSeq: true, Seq: seq}
	var region []byte
	if version >= gre.VersionCur {
		hdr.ProtType = gre.ProtoVSF
		region = gre.VSFProto{Type: gre.VSFTypeRIST, Subtype: vsfSubtype}.AppendTo(nil)
		region = append(region, body...)
	} else {
		hdr.ProtType = proto
		region = body
	}
	if c.sendKey == nil {
		out, err := hdr.AppendTo(dst)
		if err != nil {
			return dst, err
		}
		return append(out, region...), nil
	}
	ct, err := c.sendKey.Encrypt(seq, nil, region)
	if err != nil {
		return dst, err
	}
	hdr.HasKey = true
	hdr.KeySize256 = c.keySize256
	hdr.Nonce = c.sendKey.Nonce()
	out, err := hdr.AppendTo(dst)
	if err != nil {
		return dst, err
	}
	return append(out, ct...), nil
}

// encodeKeepalive frames a GRE keepalive carrying this node's MAC and capability
// bits, at the negotiated GRE version (see frameControl).
func (c *mainCodec) encodeKeepalive(dst []byte, ka gre.Keepalive, version uint8) ([]byte, error) {
	return c.frameControl(dst, ka.AppendTo(nil), version, gre.ProtoKeepalive, gre.VSFSubtypeKeepalive)
}

// encodeBufferNeg frames a VSF buffer-negotiation message (always GRE version 2;
// libRIST only sends/parses it at version >= 2).
func (c *mainCodec) encodeBufferNeg(dst []byte, bn gre.BufferNegotiation) ([]byte, error) {
	return c.frameControl(dst, bn.AppendTo(nil), gre.VersionCur, gre.ProtoVSF, gre.VSFSubtypeBufferNegotiation)
}

// peekControl classifies one inbound Main datagram for the GRE control path. It
// always returns the sender's GRE version (read cheaply from the header, for the
// monotonic version upgrade) and, for a version-1 keepalive (ProtoKeepalive),
// decodes the keepalive body so the caller can learn the peer's capabilities and
// MAC. A version-2 VSF datagram returns controlNone with its version — its
// subtype lives inside the (possibly encrypted) region, which decodeMain owns
// (decrypting once, avoiding a double-decrypt here). Returns ok=false (via the
// version 0 / controlNone result) only on a malformed GRE header. Never panics.
func (c *mainCodec) peekControl(b []byte) (kind controlKind, ka gre.Keepalive, version uint8, err error) {
	hdr, off, perr := gre.Parse(b)
	if perr != nil {
		return controlNone, ka, 0, nil
	}
	version = hdr.Version
	if hdr.ProtType != gre.ProtoKeepalive {
		return controlNone, ka, version, nil
	}
	region := b[off:]
	if hdr.HasKey {
		if c.recvKey == nil {
			return controlNone, ka, version, nil
		}
		c.recvKey.SetKeyBits(hBitKeySize(hdr.KeySize256))
		pt, derr := c.recvKey.Decrypt(hdr.Nonce, hdr.Seq, nil, region)
		if derr != nil {
			return controlKeepalive, ka, version, derr // it IS a keepalive, just undecodable
		}
		region = pt
	}
	ka, err = gre.ParseKeepalive(region)
	return controlKeepalive, ka, version, err
}

// encodeOOB frames an out-of-band data payload (libRIST RIST_PAYLOAD_TYPE_DATA_OOB):
// GRE FULL framing (prot_type 0x0800) with NO reduced-overhead header and NO RTP
// header — the raw OOB bytes follow the GRE header directly, encrypted under the
// PSK when one is configured (matching libRIST's send_data: OOB participates in
// PSK but never in ARQ). The GRE sequence counter is shared with media/RTCP (it
// is the AES IV), so OOB and media advance one monotonic sequence.
func (c *mainCodec) encodeOOB(dst, payload []byte) ([]byte, error) {
	seq := c.greSeq
	c.greSeq++
	hdr := gre.Header{
		Version:  gre.VersionMin,
		HasSeq:   true,
		ProtType: gre.ProtoFull,
		Seq:      seq,
	}
	if c.sendKey == nil {
		out, err := hdr.AppendTo(dst)
		if err != nil {
			return dst, err
		}
		return append(out, payload...), nil
	}
	ct, err := c.sendKey.Encrypt(seq, nil, payload)
	if err != nil {
		return dst, err
	}
	hdr.HasKey = true
	hdr.KeySize256 = c.keySize256
	hdr.Nonce = c.sendKey.Nonce()
	out, err := hdr.AppendTo(dst)
	if err != nil {
		return dst, err
	}
	return append(out, ct...), nil
}

// peekOOB reports whether b is an out-of-band data datagram (GRE FULL framing)
// and, if so, returns its decrypted payload. It mirrors peekEAPOL but, unlike
// EAPOL, OOB participates in PSK encryption, so it uses the codec's decryptor.
// ok is true whenever b is GRE-FULL (an OOB datagram) regardless of decode
// success, so the caller routes it to OOB delivery rather than the media demux.
// It never panics on arbitrary input.
func (c *mainCodec) peekOOB(b []byte) (oob []byte, ok bool, err error) {
	hdr, off, perr := gre.Parse(b)
	if perr != nil || hdr.ProtType != gre.ProtoFull {
		return nil, false, nil
	}
	region := b[off:]
	// Honor the per-packet K bit (see decodeMain): a cleartext OOB datagram is
	// returned as cleartext even when a decryptor is configured.
	if hdr.HasKey {
		if c.recvKey == nil {
			return nil, true, fmt.Errorf("rist: main: encrypted OOB but no decryptor configured")
		}
		c.recvKey.SetKeyBits(hBitKeySize(hdr.KeySize256))
		pt, derr := c.recvKey.Decrypt(hdr.Nonce, hdr.Seq, nil, region)
		if derr != nil {
			return nil, true, derr
		}
		return pt, true, nil
	}
	return region, true, nil
}

// encodeEAPOL frames an EAP-over-GRE authentication payload: the GRE header
// (version 1, sequence present, protocol type EAPOL) followed by the EAP
// payload, never encrypted (libRIST excludes EAPOL from PSK). It
// increments the GRE sequence once per call, like frame.
func (c *mainCodec) encodeEAPOL(dst, eap []byte) ([]byte, error) {
	seq := c.greSeq
	c.greSeq++
	hdr := gre.Header{
		Version:  gre.VersionMin,
		HasSeq:   true,
		ProtType: gre.ProtoEAPOL,
		Seq:      seq,
	}
	out, err := hdr.AppendTo(dst)
	if err != nil {
		return dst, err
	}
	return append(out, eap...), nil
}

// peekEAPOL reports whether b is an EAP-over-GRE authentication frame and, if
// so, returns the EAP payload (the bytes after the GRE header; EAPOL is never
// encrypted). The host runs it before decodeMain so authentication frames route
// to the EAP state machine instead of the media/RTCP demux. It never panics on
// arbitrary input.
func (c *mainCodec) peekEAPOL(b []byte) (eap []byte, ok bool) {
	hdr, off, err := gre.Parse(b)
	if err != nil || hdr.ProtType != gre.ProtoEAPOL {
		return nil, false
	}
	return b[off:], true
}

// decodeMain parses one Main-profile datagram. It returns isMedia true with the
// reconstructed MediaPacket when the inner packet is RTP media, or isMedia
// false with the decoded feedback list when it is compound RTCP, demultiplexing
// on the inner packet's payload-type byte. Arbitrary,
// truncated, or short-ciphertext input returns an error and never panics.
//
// nackRef is the host's current send position; it widens the 16-bit sequences
// of any NACK not preceded by an EXTSEQ packet (mirroring the Simple codec's
// decodeFeedback nackRef argument). It is ignored on the media path.
//
// The returned MediaPacket's Payload may alias internal scratch produced by
// decryption or NPD expansion; the caller must treat it as owned until the
// packet is delivered, per the flow ownership note. Decoded Feedback values own
// their slices (rtcp.ParseCompound does not alias, and NACK widening allocates).
func (c *mainCodec) decodeMain(b []byte, nackRef uint32) (isMedia bool, pkt wire.MediaPacket, fbs []wire.Feedback, err error) {
	hdr, off, err := gre.Parse(b)
	if err != nil {
		return false, wire.MediaPacket{}, nil, err
	}
	// Accept version-1 reduced framing and the version-2 VSF wrapper. The VSF
	// proto sits in the region after the GRE sequence, so (when encrypted) it is
	// inside the AES-CTR region and is unwrapped after decryption below.
	isVSF := false
	switch hdr.ProtType {
	case gre.ProtoReduced:
	case gre.ProtoVSF:
		isVSF = true
	default:
		return false, wire.MediaPacket{}, nil, fmt.Errorf("rist: main: GRE proto 0x%04x, want reduced", hdr.ProtType)
	}
	region := b[off:]

	// Decrypt the reduced header + inner region when the per-packet GRE K bit is
	// set. libRIST keys per-packet on the K bit (CHECK_BIT(gre->flags1,5)), NOT on
	// a global "is a key configured" flag: a peer may legitimately mix cleartext
	// and encrypted datagrams (the EAP-SRP use_key_as_passphrase mode encrypts only
	// the receiver->sender feedback direction and leaves sender->receiver media in
	// the clear). So a cleartext datagram is decoded as cleartext even when a
	// decryptor is configured.
	if hdr.HasKey {
		if c.recvKey == nil {
			return false, wire.MediaPacket{}, nil, fmt.Errorf("rist: main: encrypted datagram but no decryptor configured")
		}
		// Honor the GRE H bit: derive the decryption key at the size the sender
		// signalled, so a peer configured with a different aes-type still
		// interoperates. No-op when unchanged.
		c.recvKey.SetKeyBits(hBitKeySize(hdr.KeySize256))
		region, err = c.recvKey.Decrypt(hdr.Nonce, hdr.Seq, nil, region)
		if err != nil {
			return false, wire.MediaPacket{}, nil, err
		}
	}

	// Unwrap the version-2 VSF proto (now decrypted): libRIST maps subtype
	// 0x0000->REDUCED, 0x8000->KEEPALIVE, 0x8002->BUFFER_NEGOTIATION. Only
	// REDUCED carries media/RTCP we decode; keepalive and buffer-negotiation are
	// liveness/handshake control already served at the peer layer, so we accept
	// them without error or action rather than dropping the datagram.
	if isVSF {
		vsf, vn, verr := gre.ParseVSFProto(region)
		if verr != nil {
			return false, wire.MediaPacket{}, nil, verr
		}
		if vsf.Subtype != gre.VSFSubtypeReduced {
			return false, wire.MediaPacket{}, nil, nil
		}
		region = region[vn:]
	}

	// Strip the reduced-overhead header; the inner packet follows.
	if _, n, err := gre.ParseReduced(region); err != nil {
		return false, wire.MediaPacket{}, nil, err
	} else {
		region = region[n:]
	}

	// Demux on the inner packet's payload-type byte (the authoritative rule;
	// the reduced-header port is not consulted). PT 200-205 (minus 128 => 72-77
	// after masking the marker bit) is RTCP; everything else is RTP media.
	if len(region) <= rtcpPTByteLow {
		return false, wire.MediaPacket{}, nil, fmt.Errorf("rist: main: inner packet too short to demux")
	}
	pt := region[rtcpPTByteLow] & 0x7f
	if pt >= rtcpPTMin && pt <= rtcpPTMax {
		fbs, err = c.decodeFeedbackMain(region, nackRef)
		return false, wire.MediaPacket{}, fbs, err
	}
	pkt, err = c.decodeMediaMain(region)
	return true, pkt, nil, err
}

// decodeMediaMain reconstructs a MediaPacket from an inner RTP packet. When the
// RTP X bit is set and the extension is the RIST NPD extension (0x5249) at its
// canonical shape — length 1, i.e. a four-byte payload — the payload is
// NPD-expanded if the N flag is set. The 32-bit media sequence ALWAYS widens by
// rollover counting via the embedded mediaDecoder, exactly as the Simple codec
// does: the extension's seq_ext is ignored because libRIST never populates it
// on this path and a non-zero value would otherwise pin
// the high bits and break across the 16-bit wrap. A retransmit reconstructs to
// the same (Seq, SourceTime) as its original.
func (c *mainCodec) decodeMediaMain(b []byte) (wire.MediaPacket, error) {
	var p rtp.Packet
	if err := p.Unmarshal(b); err != nil {
		return wire.MediaPacket{}, err
	}
	if p.Version != rtp.Version {
		return wire.MediaPacket{}, fmt.Errorf("rist: main: rtp version %d, want 2", p.Version)
	}

	payload := p.Payload
	// Honor the RIST NPD extension only at its canonical shape: identifier
	// 0x5249 and length 1 (a four-byte payload). libRIST gates NPD expansion the
	// same way (be16toh(length)==1) and otherwise treats the
	// bytes as media rather than rejecting, so a non-canonical extension is
	// ignored here too. Pinning the payload length to 4 also makes npd.ParseExt's
	// length validation meaningful (extWireBytes synthesizes the length field).
	if p.Extension && p.ExtensionProfile == npd.Identifier && len(p.ExtensionPayload) == npdExtPayloadLen {
		ext, _, perr := npd.ParseExt(extWireBytes(p.ExtensionProfile, p.ExtensionPayload))
		if perr != nil {
			return wire.MediaPacket{}, perr
		}
		if ext.NPD {
			expanded, eerr := npd.Expand(nil, payload, npd.NPDBits(ext.Size204, ext.NullBitmap))
			if eerr != nil {
				return wire.MediaPacket{}, eerr
			}
			payload = expanded
		}
	}

	// Reconstruct the 32-bit sequence and NTP-64 source time, both by rollover
	// counting anchored at the first packet (the Main wire carries only the
	// 16-bit RTP sequence and the 32-bit RTP timestamp), so a retransmit and its
	// original reconstruct identically within the recovery window.
	var seq32 uint32
	var ticks int64
	if !c.dec.started {
		c.dec.started = true
		seq32 = uint32(p.SequenceNumber)
		ticks = int64(p.Timestamp)
	} else {
		seq32 = widenSeq(p.SequenceNumber, c.dec.refSeq)
		ticks = widenTicks(p.Timestamp, c.dec.refTicks)
	}
	c.dec.refSeq = seq32
	c.dec.refTicks = ticks

	src := uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(microsFromRTPTicks(ticks))))
	return wire.MediaPacket{
		Seq:        seq32,
		SourceTime: src,
		SSRC:       rtp.NormalizeSSRC(p.SSRC),
		Payload:    payload,
		Retransmit: rtp.IsRetransmit(p.SSRC),
	}, nil
}

// extWireBytes reassembles the 8-byte RIST RTP header extension (the 4-byte
// RFC 3550 extension header — profile and length=1 — followed by the 4-byte
// extension payload) so it can be parsed by npd.ParseExt, which validates the
// identifier and length. The RTP decoder splits these apart (profile in a field,
// payload bytes in a slice); this rejoins them without copying the profile into
// the model twice.
func extWireBytes(profile uint16, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	b[0] = byte(profile >> 8)
	b[1] = byte(profile)
	b[2] = byte(npd.Length >> 8)
	b[3] = byte(npd.Length)
	copy(b[4:], payload)
	return b
}

// decodeFeedbackMain parses a compound RTCP datagram into normalized feedback,
// folding each EXTSEQ packet's high 16 bits into the NACK packets that follow
// it (TR-06-2 §8.4). NACK sequences without a preceding EXTSEQ widen to at-most
// nackRef (the host's send position), as in the Simple codec's decodeFeedback;
// with an EXTSEQ in force the high bits are taken authoritatively from it.
// SR/RR/SDES are dropped — the core has no use for them at this stage.
func (c *mainCodec) decodeFeedbackMain(b []byte, nackRef uint32) ([]wire.Feedback, error) {
	pkts, err := rtcp.ParseCompound(b)
	if err != nil {
		return nil, err
	}
	var (
		out        []wire.Feedback
		seqHigh    uint16
		haveExtSeq bool
	)
	for _, p := range pkts {
		switch pk := p.(type) {
		case rtcp.ExtSeq:
			seqHigh = pk.SeqHigh
			haveExtSeq = true
		case rtcp.RangeNACK:
			out = append(out, c.foldNACK(pk.MediaSSRC, pk.MissingSeqs(), seqHigh, haveExtSeq, nackRef))
			haveExtSeq = false // an EXTSEQ qualifies the NACK(s) that follow it
		case rtcp.BitmaskNACK:
			out = append(out, c.foldNACK(pk.MediaSSRC, pk.MissingSeqs(), seqHigh, haveExtSeq, nackRef))
			haveExtSeq = false
		case rtcp.EchoRequest:
			out = append(out, wire.RttEchoRequest{SSRC: pk.SSRC, Timestamp: pk.Timestamp})
		case rtcp.EchoResponse:
			out = append(out, wire.RttEchoResponse{SSRC: pk.SSRC, Timestamp: pk.Timestamp, ProcessingDelay: pk.ProcessingDelay})
		case rtcp.LinkQualityReport:
			// Source adaptation (TR-06-4 Part 1 §5.3): the Simple-profile LQM RR
			// carried transparently over the GRE tunnel; cross the waist as
			// wire.LinkQuality for the host's rate controller.
			out = append(out, wire.LinkQuality{LQM: pk.LQM})
		}
	}
	return out, nil
}

// foldNACK widens a NACK's 16-bit sequence list to 32 bits. When an EXTSEQ
// preceded this NACK its SeqHigh is prepended to every entry (the authoritative
// TR-06-2 §8.4 widening); otherwise the entries widen to at-most nackRef, the
// host's send position, matching the Simple codec's nackToWire. nackRef must be
// the sender's send position, NOT the media decoder's reference — the side that
// receives NACKs (the sender) never decodes inbound media, so c.dec is unset
// there.
func (c *mainCodec) foldNACK(ssrc uint32, narrow []uint32, seqHigh uint16, haveExtSeq bool, nackRef uint32) wire.NackRequest {
	wide := make([]uint32, len(narrow))
	if haveExtSeq {
		for i, s := range narrow {
			wide[i] = uint32(seqHigh)<<16 | (s & 0xFFFF)
		}
	} else {
		for i, s := range narrow {
			wide[i] = widenSeqAtMost(uint16(s), nackRef)
		}
	}
	return wire.NackRequest{SSRC: ssrc, Missing: wide}
}
