package session

import (
	"time"

	"github.com/zsiec/ristgo/internal/bonding"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
)

// Write enqueues one application payload for transmission (sender role). It
// copies p — the flow retains the payload in its retransmit history, so the
// caller may reuse its buffer once Write returns. It blocks until the payload
// is accepted by the event loop (back-pressure when the loop is saturated),
// the write deadline passes (ErrTimeout), or the session closes (ErrClosed).
//
// Write is not safe to call from multiple goroutines concurrently.
func (s *Session) Write(p []byte) error {
	cp := make([]byte, len(p))
	copy(cp, p)
	for {
		// A Write on a closed session must report the close reason and never
		// enqueue into a buffer the (exited) loop will not drain.
		select {
		case <-s.done:
			return s.closeReason()
		default:
		}
		timer, expired := s.deadlineTimerFor(s.writeDeadline.Load())
		if expired {
			return s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case s.appIn <- cp:
			stopOptTimer(timer)
			return nil
		case <-s.done:
			stopOptTimer(timer)
			return s.closeReason()
		case <-timeout:
			return s.cfg.ErrTimeout
		case <-s.writeWake:
			stopOptTimer(timer) // deadline changed; re-evaluate
		}
	}
}

// Read returns the next in-order, ARQ-recovered media payload (receiver role).
// It has stream semantics: a payload larger than buf is returned across
// successive calls. It blocks until data is available, the read deadline
// passes (ErrTimeout), or the session closes (ErrClosed, after any buffered
// payloads are drained).
//
// Read is not safe to call from multiple goroutines concurrently.
func (s *Session) Read(buf []byte) (int, error) {
	if len(s.leftover) > 0 {
		n := copy(buf, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}
	for {
		// Deliver buffered data ahead of everything else, even after close.
		select {
		case p := <-s.delivery:
			return s.take(buf, p), nil
		default:
		}
		timer, expired := s.deadlineTimerFor(s.readDeadline.Load())
		if expired {
			return 0, s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case p := <-s.delivery:
			stopOptTimer(timer)
			return s.take(buf, p), nil
		case <-s.done:
			stopOptTimer(timer)
			select {
			case p := <-s.delivery:
				return s.take(buf, p), nil
			default:
				return 0, s.closeReason()
			}
		case <-timeout:
			return 0, s.cfg.ErrTimeout
		case <-s.readWake:
			stopOptTimer(timer) // deadline changed; re-evaluate
		}
	}
}

// WriteOOB enqueues one out-of-band datagram for transmission under GRE protocol
// type proto (Main/Advanced profiles only). OOB rides the same socket as media but
// bypasses ARQ entirely — fire-and-forget, like libRIST's rist_oob_write. It
// returns ErrOOBUnsupported when the session has no OOB channel (the Simple
// profile). It blocks under back-pressure, honoring the write deadline (ErrTimeout)
// and close (ErrClosed). The caller is responsible for proto being non-reserved.
func (s *Session) WriteOOB(proto uint16, p []byte) error {
	if s.oobIn == nil {
		return s.cfg.ErrOOBUnsupported
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	od := oobData{proto: proto, data: cp}
	for {
		select {
		case <-s.done:
			return s.closeReason()
		default:
		}
		timer, expired := s.deadlineTimerFor(s.writeDeadline.Load())
		if expired {
			return s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case s.oobIn <- od:
			stopOptTimer(timer)
			return nil
		case <-s.done:
			stopOptTimer(timer)
			return s.closeReason()
		case <-timeout:
			return s.cfg.ErrTimeout
		case <-s.writeWake:
			stopOptTimer(timer)
		}
	}
}

// WriteFlowAttribute enqueues one Advanced Flow Attribute control message
// (TR-06-3 §5.3.7) carrying the UTF-8 JSON body for transmission to the peer. It
// is an Advanced-profile sender feature: the receiver surfaces the body to its
// OnFlowAttr callback. Like WriteOOB it is fire-and-forget (no ARQ) and blocks
// under back-pressure, honoring the write deadline (ErrTimeout) and close
// (ErrClosed). It returns ErrFlowAttrUnsupported on a non-Advanced session.
func (s *Session) WriteFlowAttribute(json []byte) error {
	if s.flowAttrIn == nil {
		return s.cfg.ErrFlowAttrUnsupported
	}
	cp := make([]byte, len(json))
	copy(cp, json)
	for {
		select {
		case <-s.done:
			return s.closeReason()
		default:
		}
		timer, expired := s.deadlineTimerFor(s.writeDeadline.Load())
		if expired {
			return s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case s.flowAttrIn <- cp:
			stopOptTimer(timer)
			return nil
		case <-s.done:
			stopOptTimer(timer)
			return s.closeReason()
		case <-timeout:
			return s.cfg.ErrTimeout
		case <-s.writeWake:
			stopOptTimer(timer)
		}
	}
}

// ReadOOB returns the next received out-of-band datagram and its GRE protocol type
// (Main/Advanced only). Unlike Read it is datagram-oriented: each call returns
// exactly one OOB payload, truncated to len(buf). It returns ErrOOBUnsupported on
// the Simple profile, and blocks until an OOB datagram arrives, the read deadline
// passes (ErrTimeout), or the session closes (ErrClosed, after draining buffered
// OOB).
func (s *Session) ReadOOB(buf []byte) (n int, proto uint16, err error) {
	if s.oobOut == nil {
		return 0, 0, s.cfg.ErrOOBUnsupported
	}
	for {
		select {
		case od := <-s.oobOut:
			return copy(buf, od.data), od.proto, nil
		default:
		}
		timer, expired := s.deadlineTimerFor(s.readDeadline.Load())
		if expired {
			return 0, 0, s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case od := <-s.oobOut:
			stopOptTimer(timer)
			return copy(buf, od.data), od.proto, nil
		case <-s.done:
			stopOptTimer(timer)
			select {
			case od := <-s.oobOut:
				return copy(buf, od.data), od.proto, nil
			default:
				return 0, 0, s.closeReason()
			}
		case <-timeout:
			return 0, 0, s.cfg.ErrTimeout
		case <-s.readWake:
			stopOptTimer(timer)
		}
	}
}

// take copies as much of payload as fits into buf, stashing any remainder for
// the next Read (stream semantics for io.Copy).
func (s *Session) take(buf, payload []byte) int {
	n := copy(buf, payload)
	if n < len(payload) {
		s.leftover = payload[n:]
	}
	return n
}

// deadlineTimerFor returns a timer firing at dl, or expired=true when dl is
// already in the past. Both are zero/false when no deadline is set.
func (s *Session) deadlineTimerFor(dl *time.Time) (timer *time.Timer, expired bool) {
	if dl == nil || dl.IsZero() {
		return nil, false
	}
	d := time.Until(*dl)
	if d <= 0 {
		return nil, true
	}
	return time.NewTimer(d), false
}

func stopOptTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// SetReadDeadline sets the deadline for Read; a zero time clears it. A pending
// Read is woken so it observes the new deadline.
func (s *Session) SetReadDeadline(t time.Time) {
	s.readDeadline.Store(&t)
	select {
	case s.readWake <- struct{}{}:
	default:
	}
}

// SetWriteDeadline sets the deadline for Write; a zero time clears it. A
// pending Write is woken so it observes the new deadline.
func (s *Session) SetWriteDeadline(t time.Time) {
	s.writeDeadline.Store(&t)
	select {
	case s.writeWake <- struct{}{}:
	default:
	}
}

// appBlock is one per-block media submit (Sender.SendBlock, USE_SEQ + ts_ntp)
// delivered to the event loop. A nil seq/sourceTime takes the flow's auto sequence /
// now-derived timestamp; non-nil values are used verbatim.
type appBlock struct {
	payload    []byte
	seq        *uint32
	sourceTime *uint64
}

// mediaBlock is one recovered, in-order delivery with its wire identity — the
// receive-side counterpart of appBlock, carried to a reflector pump so it can re-emit
// the packet preserving (seq, sourceTime).
type mediaBlock struct {
	seq         uint32
	sourceTime  uint64
	virtSrcPort uint16
	virtDstPort uint16
	payload     []byte
}

// RecvBlock returns the next recovered, in-order media block: its sequence number,
// source timestamp, decoded virtual ports, and payload. Used by a reflector-input
// session (NewMainReflectorInput) and by a block-delivery receiver (Config.BlockDelivery).
// It blocks until a block is available or the session closes, returning the close reason
// on close. The payload is a fresh copy the caller owns.
func (s *Session) RecvBlock() (seq uint32, sourceTime uint64, virtSrc, virtDst uint16, payload []byte, err error) {
	select {
	case b, ok := <-s.blockOut:
		if !ok {
			return 0, 0, 0, 0, nil, s.closeReason()
		}
		return b.seq, b.sourceTime, b.virtSrcPort, b.virtDstPort, b.payload, nil
	case <-s.done:
		return 0, 0, 0, 0, nil, s.closeReason()
	}
}

// SendBlock submits one media payload with optional explicit sequence number and/or
// source timestamp (Sender.SendBlock, libRIST USE_SEQ + ts_ntp), marshalled onto the
// event loop. It returns ErrSendBlockUnsupported on a non-Main session (the block
// channel is wired for the single-socket Main profile) and the close reason once the
// session is closed. payload must not be mutated after the call (the flow retains it).
func (s *Session) SendBlock(payload []byte, seq *uint32, sourceTime *uint64) error {
	if s.blockIn == nil {
		return s.cfg.ErrSendBlockUnsupported
	}
	select {
	case s.blockIn <- appBlock{payload: payload, seq: seq, sourceTime: sourceTime}:
		return nil
	case <-s.done:
		return s.closeReason()
	}
}

// ctrlKind tags a runtime config setter delivered over Session.ctrlCmd.
type ctrlKind uint8

const (
	ctrlNackType ctrlKind = iota // set the live NACK format (b: bitmask)
	ctrlRTTMult                  // set the recovery-buffer RTT multiplier (n)
	ctrlNPD                      // toggle null-packet deletion (b)
)

// ctrlSet is one runtime config change marshalled onto the event loop, which owns
// the flow core, the codec, and the live cfg.Bitmask. It is the setter analogue of
// weightSet (BondedSender.SetWeight).
type ctrlSet struct {
	kind ctrlKind
	b    bool // bitmask (nack-type) or on (NPD)
	n    int  // rtt multiplier
}

// applyCtrl applies one runtime config setter on the loop goroutine.
func (s *Session) applyCtrl(c ctrlSet) {
	switch c.kind {
	case ctrlNackType:
		// Every encodeFeedback site reads s.cfg.Bitmask live, so this one mutation
		// switches the NACK format from the next emitted feedback.
		s.cfg.Bitmask = c.b
	case ctrlRTTMult:
		s.flow.SetRTTMultiplier(c.n)
	case ctrlNPD:
		// The Main bonded sender also encodes media through the single s.main codec,
		// so this covers both single and bonded Main senders.
		if s.main != nil {
			s.main.setNPD(c.b)
		}
	}
}

// sendCtrl marshals one runtime config setter onto the event loop, returning the
// close reason if the session has shut down. Mirrors SetPathWeight.
func (s *Session) sendCtrl(c ctrlSet) error {
	select {
	case s.ctrlCmd <- c:
		return nil
	case <-s.done:
		return s.closeReason()
	}
}

// SetNackType switches the NACK feedback format at runtime (Receiver.SetNackType,
// libRIST rist_receiver_nack_type_set). bitmask selects RFC 4585 bitmask encoding;
// false selects RIST range. It takes effect on the next emitted NACK and is safe to
// call from any goroutine.
func (s *Session) SetNackType(bitmask bool) error {
	return s.sendCtrl(ctrlSet{kind: ctrlNackType, b: bitmask})
}

// SetRTTMultiplier sets the recovery-buffer RTT multiplier at runtime
// (Receiver.SetRTTMultiplier, libRIST rist_recovery_rtt_multiplier_set). It takes
// effect on the next auto-scale recalculation and is safe to call from any
// goroutine. Range validation is the caller's job.
func (s *Session) SetRTTMultiplier(multiplier int) error {
	return s.sendCtrl(ctrlSet{kind: ctrlRTTMult, n: multiplier})
}

// SetNullPacketDeletion toggles null-packet deletion on the send path at runtime
// (Sender.SetNullPacketDeletion, libRIST rist_sender_npd_enable/_disable). It
// returns ErrNPDUnsupported on a non-Main session (NPD is Main-only) and the close
// reason once the session is closed. Safe to call from any goroutine.
func (s *Session) SetNullPacketDeletion(on bool) error {
	if s.main == nil {
		return s.cfg.ErrNPDUnsupported
	}
	return s.sendCtrl(ctrlSet{kind: ctrlNPD, b: on})
}

// Stats returns the most recent snapshot of the flow's counters.
func (s *Session) Stats() flow.Stats {
	s.statsMu.Lock()
	v := s.statsVal
	s.statsMu.Unlock()
	return v
}

// PeerStats returns the most recent per-path peer snapshots for a bonded session, or
// nil for a non-bonded session (the host then derives a single peer from the flow).
func (s *Session) PeerStats() []bonding.PathStats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if s.statsPeers == nil {
		return nil
	}
	return append([]bonding.PathStats(nil), s.statsPeers...)
}

// Authenticated reports whether the data channel is open: true for a Simple
// session or a Main session without EAP, and for a Main+EAP session once the
// EAP-SRP handshake has succeeded. It is safe to call concurrently.
func (s *Session) Authenticated() bool { return s.authed.Load() }

// MediaPort returns the local media (even) UDP port.
func (s *Session) MediaPort() int { return s.conn.MediaPort() }

// Err returns the reason the session closed, or nil if it is still open.
func (s *Session) Err() error {
	if p := s.closeErr.Load(); p != nil {
		return *p
	}
	return nil
}

// Close shuts the session down: it stops the event loop and reader goroutines,
// closes the sockets, and waits for every goroutine to exit. It is idempotent
// and safe to call concurrently with Read/Write.
func (s *Session) Close() error {
	s.shutdown(s.cfg.ErrClosed)
	s.wg.Wait()
	return nil
}

// shutdown records the close reason and signals every goroutine exactly once.
// It is safe to call from the event loop (on session timeout or buffer
// overflow) or the application goroutine (Close); only Close waits on the
// goroutines.
func (s *Session) shutdown(reason error) {
	s.closeOnce.Do(func() {
		s.closeErr.Store(&reason)
		close(s.done)
		if !s.injected {
			s.conn.Close() // unblock the reader goroutines' blocking ReadFrom
			if s.bond != nil {
				s.closeBond() // close every path socket (conns[0] == s.conn, idempotent)
			}
		}
		if s.fecCol != nil { // separate-port FEC sockets, owned by the session
			s.fecCol.Close()
		}
		if s.fecRow != nil {
			s.fecRow.Close()
		}
		for _, c := range s.fecSockets { // bonded per-path FEC sockets, owned by the session
			c.Close()
		}
		// An injected (MultiReceiver-driven) session never owns its socket(s); the
		// MultiReceiver closes them.
	})
}

// closeReason returns the stored close reason, defaulting to ErrClosed.
func (s *Session) closeReason() error {
	if p := s.closeErr.Load(); p != nil {
		return *p
	}
	return s.cfg.ErrClosed
}

// setTimer records the flow's requested deadline for id.
func (s *Session) setTimer(id flow.TimerID, deadline clock.Timestamp) {
	s.timers[id] = deadline
}

// clearTimer cancels the flow's timer for id.
func (s *Session) clearTimer(id flow.TimerID) {
	delete(s.timers, id)
}

// earliestTimer returns the soonest pending declarative timer.
func (s *Session) earliestTimer() (id flow.TimerID, deadline clock.Timestamp, ok bool) {
	for tid, d := range s.timers {
		if !ok || d.Before(deadline) {
			id, deadline, ok = tid, d, true
		}
	}
	return id, deadline, ok
}

// rearm resets the host time.Timer to the earliest pending declarative
// deadline, or leaves it stopped when none remain.
func (s *Session) rearm(timer *time.Timer, now clock.Timestamp) {
	stopTimer(timer)
	if _, deadline, ok := s.earliestTimer(); ok {
		d := deadline.Sub(now).Duration()
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
	}
}
