package session

import (
	"net"

	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/bonding"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/peer"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/socket"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file is the link-bonding / SMPTE 2022-7 host: N network paths feeding one
// flow. It is the Simple-profile bonded analog of the single-path host — the
// 2022-7 merge itself lives in the flow core (one seq-indexed ring deduplicated
// by (Seq, SourceTime)); this host just fans transmissions across the paths and
// feeds every path's arrivals into that one ring.
//
// # Topology
//
// A bonded RECEIVER binds one socket per path (conns[i]); each path learns its
// own sender address and feeds media into the flow with its path index. A
// bonded SENDER uses one socket and a list of remote {media, rtcp} address pairs
// (remotes[i]); it DUPLICATES every media datagram to all of them (full
// redundancy) so identical (Seq, SourceTime) copies arrive on every path and the
// receiver merges them.
//
// # Decoder sharing
//
// Both directions transmit byte-identical RTP on every path, so the receiver
// MUST decode them with ONE shared mediaDecoder (s.mdec): a per-path decoder
// would anchor its sequence/timestamp widening independently and reconstruct
// different (Seq, SourceTime) values for the same packet on different paths,
// defeating the dedup. The loop is single-goroutine, so the shared decoder is
// safe and yields identical normalized packets for identical wire bytes.

// bondInbound is one datagram a per-path reader hands to the event loop, tagged
// with the path it arrived on (for a receiver) and whether it is RTCP.
type bondInbound struct {
	idx    uint8
	isRTCP bool
	data   []byte
	src    *net.UDPAddr
}

// bondState holds the per-path I/O and policy for a bonded session.
type bondState struct {
	group *bonding.Group

	// conns is one socket per path on a receiver, or the single send socket
	// (conns[0]) on a sender.
	conns []*socket.Conn

	// remotes is the sender's per-path {media, rtcp} destination pair; nil on a
	// receiver (which learns each path's peer from inbound traffic).
	remotes [][2]*net.UDPAddr

	// peers tracks each path's learned/known addresses and liveness.
	peers []*peer.Peer
}

// NewBondedReceiver builds a Simple-profile bonded receiver: one socket per
// path, all feeding flow into a single deduplicated ring. group must already
// have a path registered per conn (index = conn index); the constructor
// registers them if empty.
func NewBondedReceiver(conns []*socket.Conn, group *bonding.Group, cfg Config) *Session {
	s := newSession(conns[0], cfg, false)
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	bs := &bondState{group: group, conns: conns, peers: make([]*peer.Peer, len(conns))}
	for i := range conns {
		bs.peers[i] = peer.New(cfg.SessionTimeout)
		group.AddPath(uint8(i), bonding.WeightDuplicate, 0)
	}
	s.bond = bs
	s.bondIn = make(chan bondInbound, 256*len(conns))
	s.start()
	return s
}

// NewBondedSender builds a Simple-profile bonded sender: one socket that
// duplicates every media datagram to each remote {media, rtcp} pair. conn is the
// local ephemeral socket; remotes are the per-path receiver addresses.
func NewBondedSender(conn *socket.Conn, remotes [][2]*net.UDPAddr, group *bonding.Group, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	bs := &bondState{group: group, conns: []*socket.Conn{conn}, remotes: remotes, peers: make([]*peer.Peer, len(remotes))}
	for i := range remotes {
		bs.peers[i] = peer.New(cfg.SessionTimeout)
		bs.peers[i].Media = remotes[i][0]
		bs.peers[i].RTCP = remotes[i][1]
		group.AddPath(uint8(i), bonding.WeightDuplicate, 0)
	}
	// The base Session's peer guards (peer.Media/RTCP != nil) gate transmission;
	// point them at path 0 so the keepalive/feedback guards pass.
	s.peer.Media = remotes[0][0]
	s.peer.RTCP = remotes[0][1]
	s.bond = bs
	s.bondIn = make(chan bondInbound, 256)
	s.start()
	return s
}

// startBondReaders launches the per-path reader goroutines. A receiver runs a
// media and an RTCP reader per path socket; a sender runs a single RTCP reader
// on its one socket (it never receives media), and resolves the path by source
// address.
func (s *Session) startBondReaders() {
	// The Main and Advanced profiles tunnel each path over a single socket
	// (media and control demultiplexed by the codec), so one reader per path
	// suffices; the Simple profile uses an even/odd media+RTCP socket pair.
	singlePort := s.main != nil || s.adv != nil
	if s.sender {
		s.wg.Add(1)
		if singlePort {
			go s.readBond(0, false, s.bond.conns[0].ReadMedia)
		} else {
			go s.readBond(0, true, s.bond.conns[0].ReadRTCP)
		}
		return
	}
	for i, c := range s.bond.conns {
		if singlePort {
			s.wg.Add(1)
			go s.readBond(uint8(i), false, c.ReadMedia)
			continue
		}
		s.wg.Add(2)
		go s.readBond(uint8(i), false, c.ReadMedia)
		go s.readBond(uint8(i), true, c.ReadRTCP)
	}
}

// readBond reads datagrams from one path socket (media or RTCP) and forwards
// them to the loop tagged with the path index.
func (s *Session) readBond(idx uint8, isRTCP bool, read func([]byte) (int, *net.UDPAddr, error)) {
	defer s.wg.Done()
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := read(buf)
		if err != nil {
			return
		}
		select {
		case s.bondIn <- bondInbound{idx: idx, isRTCP: isRTCP, data: buf[:n], src: src}:
		case <-s.done:
			return
		}
	}
}

// handleBondInbound processes one inbound bonded datagram: it resolves the path
// (a sender resolves by source address), refreshes liveness, and routes media
// into the flow with its path index (the merge) or feedback into the flow.
func (s *Session) handleBondInbound(now clock.Timestamp, bi bondInbound) {
	idx := bi.idx
	if s.sender {
		var ok bool
		if idx, ok = s.bondPathForSrc(bi.src); !ok {
			return // a datagram from an unknown source; ignore
		}
	}
	if int(idx) >= len(s.bond.peers) {
		return
	}
	p := s.bond.peers[idx]
	p.Observe(now)
	s.peer.Observe(now)
	s.bond.group.Observe(idx, now)

	switch {
	case s.main != nil:
		s.handleBondMain(now, idx, p, bi)
	case s.adv != nil:
		s.handleBondAdv(now, idx, p, bi)
	default:
		s.handleBondSimple(now, idx, p, bi)
	}
}

// bondObserveRTT attributes an RTT-echo response in fbs to a bonded path so the
// NACK-peer selection can prefer the lower-latency return path, then feeds all
// of fbs into the flow. Shared by every profile's bonded feedback path.
func (s *Session) bondObserveRTT(now clock.Timestamp, idx uint8, fbs []wire.Feedback) {
	for _, fb := range fbs {
		if resp, ok := fb.(wire.RttEchoResponse); ok {
			sent := clock.NTPTime(resp.Timestamp).Timestamp()
			s.bond.group.ObserveRTT(idx, now.Sub(sent)-clock.Microseconds(resp.ProcessingDelay))
		}
		s.flow.FeedFeedback(now, fb)
	}
}

// handleBondSimple routes one Simple-profile bonded datagram: RTCP into feedback
// (with per-path RTT), media into the flow with its path index. Media is decoded
// with the SHARED decoder so identical wire bytes from any path reconstruct to
// the same (Seq, SourceTime), which is what the dedup merges.
func (s *Session) handleBondSimple(now clock.Timestamp, idx uint8, p *peer.Peer, bi bondInbound) {
	if bi.isRTCP {
		p.LearnRTCP(bi.src)
		if fbs, err := decodeFeedback(bi.data, s.highestSent); err == nil {
			s.bondObserveRTT(now, idx, fbs)
		}
		return
	}
	p.LearnMedia(bi.src)
	if pkt, err := s.mdec.decode(bi.data); err == nil {
		s.flow.Feed(now, idx, pkt)
		s.observeRx(now, pkt)
	}
}

// handleBondMain routes one Main-profile bonded datagram. Each path tunnels over
// one socket, so the shared Main codec demuxes media vs feedback (and OOB); media
// is fed with its path index and feedback attributed per path.
func (s *Session) handleBondMain(now clock.Timestamp, idx uint8, p *peer.Peer, bi bondInbound) {
	p.LearnMedia(bi.src)
	p.LearnRTCP(bi.src)
	if oob, ok, oerr := s.main.peekOOB(bi.data); ok {
		if oerr == nil {
			s.deliverOOB(oob)
		}
		return
	}
	isMedia, pkt, fbs, err := s.main.decodeMain(bi.data, s.highestSent)
	if err != nil {
		return
	}
	if isMedia {
		s.observeRxBytes(len(bi.data))
		s.flow.Feed(now, idx, pkt)
		s.observeRx(now, pkt)
		return
	}
	s.bondObserveRTT(now, idx, fbs)
}

// handleBondAdv routes one Advanced-profile bonded datagram: adv RTP media into
// the flow with its path index, or the Main-GRE control substrate (Type-8 or raw
// GRE RTCP) into feedback. It mirrors handleAdvInbound but is path-aware.
func (s *Session) handleBondAdv(now clock.Timestamp, idx uint8, p *peer.Peer, bi bondInbound) {
	p.LearnMedia(bi.src)
	p.LearnRTCP(bi.src)
	data := bi.data
	if len(data) >= 2 && data[0]&0xC0 == 0x80 {
		if pt := data[1] & 0x7f; pt == adv.PayloadType || pt >= 96 {
			if pr, err := adv.Parse(data); err == nil {
				if pr.EncType == adv.TypeGREMain {
					s.handleBondAdvGRE(now, idx, pr.Payload)
					return
				}
				if isMedia, pkt, fbs, derr := s.adv.decodeParsed(pr); derr == nil {
					if isMedia {
						s.observeRxBytes(len(data))
						s.flow.Feed(now, idx, pkt)
						s.observeRx(now, pkt)
					} else {
						s.bondObserveRTT(now, idx, dropAdvEchoRequests(fbs))
					}
				}
				return
			}
		}
	}
	s.handleBondAdvGRE(now, idx, data)
}

// handleBondAdvGRE decodes one Main-profile GRE datagram on a bonded Advanced
// path (the RTCP/keepalive substrate), feeding any NACK/feedback into the flow
// with per-path RTT attribution.
func (s *Session) handleBondAdvGRE(now clock.Timestamp, idx uint8, data []byte) {
	if oob, ok, oerr := s.advGRE.peekOOB(data); ok {
		if oerr == nil {
			s.deliverOOB(oob)
		}
		return
	}
	isMedia, pkt, fbs, err := s.advGRE.decodeMain(data, s.highestSent)
	if err != nil {
		return
	}
	if isMedia {
		s.observeRxBytes(len(data))
		s.flow.Feed(now, idx, pkt)
		s.observeRx(now, pkt)
		return
	}
	s.bondObserveRTT(now, idx, dropAdvEchoRequests(fbs))
}

// bondPathForSrc resolves a sender's inbound source address (a receiver path's
// RTCP socket) to its path index.
func (s *Session) bondPathForSrc(src *net.UDPAddr) (uint8, bool) {
	if src == nil {
		return 0, false
	}
	for i, r := range s.bond.remotes {
		if udpAddrEqual(src, r[1]) {
			return uint8(i), true
		}
	}
	return 0, false
}

// udpAddrEqual reports whether two UDP addresses share IP and port.
func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// sendBondMedia duplicates one encoded media datagram to every path (full 2022-7
// redundancy). It encodes ONCE with the profile codec and writes the identical
// bytes to each path's media destination. The encrypted Main/Advanced transport
// sequence (the GRE/IV seq) is therefore identical on every path, which is
// interop-safe: the dedup key is the inner RTP (Seq, SourceTime), identical
// across paths, and the receiver reads each datagram's transport seq from the
// wire (libRIST frames per-peer but the receiver merges on the same RTP key).
func (s *Session) sendBondMedia(now clock.Timestamp, pkt wire.MediaPacket) {
	s.mediaBuf = s.mediaBuf[:0]
	var (
		b   []byte
		err error
	)
	switch {
	case s.main != nil:
		b, err = s.main.encodeMainMedia(s.mediaBuf, pkt)
	case s.adv != nil:
		b, err = s.adv.encodeAdvMedia(s.mediaBuf, pkt)
	default:
		b, err = encodeMedia(s.mediaBuf, pkt)
	}
	if err != nil {
		s.logf("bond: encode media seq %d: %v", pkt.Seq, err)
		return
	}
	s.mediaBuf = b
	for i := range s.bond.remotes {
		// Skip a path proven dead (seen and then silent past the session timeout)
		// so the sender stops blasting media at a permanently-down path; a
		// never-seen path is still sent to (libRIST's hard-dead prune).
		if !s.bond.group.ShouldDuplicate(uint8(i), now) {
			continue
		}
		if err := s.bond.conns[0].WriteMedia(b, s.bond.remotes[i][0]); err != nil {
			s.logf("bond: write media path %d: %v", i, err)
		}
	}
	s.lastTx = now
}

// sendBondFeedback transmits drained feedback. A receiver sends one compound
// RTCP on the NACK-peer-selected live path (bonding.SelectNackPath); a sender
// sends its RTT-echo feedback on every path so each path's liveness/RTT is
// exercised.
func (s *Session) sendBondFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	var lead rtcp.Packet
	if s.sender {
		lead = rtcp.SenderReport{
			SSRC:    s.cfg.SSRC,
			NTP:     s.wallNTP(now), // absolute wall-clock NTP (RFC 3550); see wallNTP
			RTPTime: uint32(rtpTicksFromMicros(int64(now))),
		}
	} else {
		lead = s.receiverReport()
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	// Main and Advanced tunnel feedback as a GRE compound (the Main codec, or the
	// Advanced profile's GRE control substrate) over the single per-path socket;
	// the Simple profile sends bare compound RTCP on the odd port.
	greCodec := s.bondGRECodec()
	var (
		b   []byte
		err error
	)
	if greCodec != nil {
		b, err = greCodec.encodeMainFeedback(s.rtcpBuf, lead, fbs, s.cfg.Bitmask)
	} else {
		b, err = encodeFeedback(s.rtcpBuf, lead, s.cfg.SSRC, s.cfg.CNAME, fbs, s.cfg.Bitmask)
	}
	if err != nil {
		s.logf("bond: encode feedback: %v", err)
		return
	}
	s.rtcpBuf = b

	if s.sender {
		// Send on every path so RTT echoes and SDES reach each receiver path.
		for i := range s.bond.remotes {
			if err := s.writeBondFeedback(s.bond.conns[0], greCodec, s.bond.remotes[i][1], s.bond.remotes[i][0]); err != nil {
				s.logf("bond: write feedback path %d: %v", i, err)
			}
		}
		s.lastTx = now
		return
	}
	// Receiver: route NACK groups to the single selected live path.
	idx, ok := s.bond.group.SelectNackPath(now)
	if !ok {
		return
	}
	p := s.bond.peers[idx]
	if p.RTCP == nil {
		return // that path's return address not learned yet
	}
	if err := s.writeBondFeedback(s.bond.conns[idx], greCodec, p.RTCP, p.RTCP); err != nil {
		s.logf("bond: write feedback on path %d: %v", idx, err)
	}
	s.lastTx = now
}

// bondGRECodec returns the GRE codec a bonded session uses to tunnel feedback:
// the Main codec for a Main bonded session, the Advanced GRE control substrate
// for an Advanced one, or nil for the Simple profile (bare RTCP).
func (s *Session) bondGRECodec() *mainCodec {
	if s.main != nil {
		return s.main
	}
	return s.advGRE
}

// writeBondFeedback writes one encoded feedback datagram to a path. Single-port
// profiles (greCodec != nil) write the media-side socket/address; the Simple
// profile writes the RTCP socket/odd-port address.
func (s *Session) writeBondFeedback(conn *socket.Conn, greCodec *mainCodec, simpleRTCP, singlePort *net.UDPAddr) error {
	if greCodec != nil {
		return conn.WriteMedia(s.rtcpBuf, singlePort)
	}
	return conn.WriteRTCP(s.rtcpBuf, simpleRTCP)
}

// sendBondKeepalive emits a periodic keepalive. A sender sends SR + SDES +
// RTT-echo on every path (sendBondFeedback already fans out). A receiver fans
// its RR + RTT-echo request out to EVERY learned path — not just the selected
// NACK path — so each path's RTT and return-path liveness are exercised;
// otherwise only the selected path's RTT is ever measured and the NACK-peer
// RTT tie-break has no data. NACK groups still route to the single selected path
// via sendBondFeedback.
func (s *Session) sendBondKeepalive(now clock.Timestamp) {
	echo := []wire.Feedback{wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))}}
	if s.sender {
		s.sendBondFeedback(echo, now)
		return
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	greCodec := s.bondGRECodec()
	var (
		b   []byte
		err error
	)
	if greCodec != nil {
		b, err = greCodec.encodeMainFeedback(s.rtcpBuf, s.receiverReport(), echo, s.cfg.Bitmask)
	} else {
		b, err = encodeFeedback(s.rtcpBuf, s.receiverReport(), s.cfg.SSRC, s.cfg.CNAME, echo, s.cfg.Bitmask)
	}
	if err != nil {
		s.logf("bond: encode keepalive: %v", err)
		return
	}
	s.rtcpBuf = b
	sent := false
	for i := range s.bond.peers {
		p := s.bond.peers[i]
		if p.RTCP == nil {
			continue // path's return address not learned yet
		}
		if err := s.writeBondFeedback(s.bond.conns[i], greCodec, p.RTCP, p.RTCP); err != nil {
			s.logf("bond: write keepalive path %d: %v", i, err)
			continue
		}
		sent = true
	}
	if sent {
		s.lastTx = now
	}
}

// tickBond ages the paths and logs any that died this interval. (The flow keeps
// running on the survivors; the merge needs no notification.)
func (s *Session) tickBond(now clock.Timestamp) {
	for _, idx := range s.bond.group.Tick(now) {
		s.logf("bond: path %d declared dead", idx)
	}
}

// closeBond closes every path socket. Called from shutdown for a bonded session.
func (s *Session) closeBond() {
	for _, c := range s.bond.conns {
		c.Close()
	}
}
