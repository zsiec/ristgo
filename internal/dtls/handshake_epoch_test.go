package dtls

import (
	"strings"
	"testing"
	"time"
)

// TestReassemblerTracksEpoch is the L8 unit-level check: the reassembler tags a
// reassembled message with the record epoch its fragments arrived under, so the
// handshake can require a Finished to be epoch-1 protected.
func TestReassemblerTracksEpoch(t *testing.T) {
	r := newReassembler()
	// An epoch-0 (plaintext) message at the cursor.
	f0 := parsedFragment{typ: typeClientHello, totalLen: 1, seq: 0, fragOff: 0, frag: []byte{0x01}, epoch: 0}
	if err := r.accept(f0); err != nil {
		t.Fatalf("accept epoch-0: %v", err)
	}
	m0, ok := r.nextMessage()
	if !ok || m0.epoch != 0 {
		t.Fatalf("message 0 epoch = %d ok=%v, want epoch 0", m0.epoch, ok)
	}
	// An epoch-1 (protected) message next.
	f1 := parsedFragment{typ: typeFinished, totalLen: 12, seq: 1, fragOff: 0, frag: make([]byte, 12), epoch: 1}
	if err := r.accept(f1); err != nil {
		t.Fatalf("accept epoch-1: %v", err)
	}
	m1, ok := r.nextMessage()
	if !ok || m1.epoch != 1 {
		t.Fatalf("message 1 epoch = %d ok=%v, want epoch 1", m1.epoch, ok)
	}
}

// plaintextFinishedClientHandshake drives a PSK client that emits its Finished as
// an epoch-0 PLAINTEXT handshake record (with the correct verify_data) instead of
// an epoch-1 protected one. A conforming server must reject it on the epoch tag
// alone (L8), before verify_data even matters.
func (c *Conn) plaintextFinishedClientHandshake() error {
	cfg := c.cfg
	overall := time.Now().Add(cfg.HandshakeTimeout)
	c.reasm = newReassembler()
	c.curRetrans = cfg.RetransmitTimeout

	suites := []uint16{tlsPSKWithAES128GCMSHA256}
	clientRandom := make([]byte, randomLen)
	if _, err := readFullRand(cfg, clientRandom); err != nil {
		return err
	}
	chBody := func(cookie []byte) []byte {
		body, _ := clientHello{
			version:         versionDTLS12,
			random:          clientRandom,
			cookie:          cookie,
			cipherSuites:    suites,
			extMasterSecret: true,
		}.marshalBody()
		return body
	}

	f1 := &flight{}
	c.emitHandshake(f1, typeClientHello, 0, chBody(nil), false)
	if err := c.sendFlight(f1); err != nil {
		return err
	}
	msg, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	hvr, err := parseHelloVerifyRequest(msg.body)
	if err != nil {
		return err
	}
	f3 := &flight{}
	c.emitHandshake(f3, typeClientHello, 0, chBody(hvr.cookie), true)
	if err := c.sendFlight(f3); err != nil {
		return err
	}

	sh, err := c.readServerHello(overall)
	if err != nil {
		return err
	}
	serverRandom := sh.random
	useEMS := sh.extMasterSecret
	for done := false; !done; {
		msg, err = c.readHandshakeMessage(overall)
		if err != nil {
			return err
		}
		c.addToTranscript(msg)
		if msg.typ == typeServerHelloDone {
			done = true
		}
	}

	pms := pskPremaster(cfg.PSK)
	clientKX, _ := clientKeyExchangePSK{identity: cfg.PSKIdentity}.marshalBody()

	// Flight 5: ClientKeyExchange, CCS, then Finished AT EPOCH 0 (the attack).
	f5 := &flight{}
	c.emitHandshake(f5, typeClientKeyExchange, 0, clientKX, true)
	master := c.deriveMaster(pms, useEMS, clientRandom, serverRandom)
	keys, err := deriveKeys(master, clientRandom, serverRandom)
	if err != nil {
		return err
	}
	c.keys = keys
	c.keysReady = true
	emitCCS(f5)
	clientVerify := finishedVerifyData(master, labelClientFinished, c.transcriptHash())
	// Epoch 0 here (a conforming client uses epoch 1).
	c.emitHandshake(f5, typeFinished, 0, marshalFinished(clientVerify), true)
	if err := c.sendFlight(f5); err != nil {
		return err
	}

	_, err = c.readHandshakeMessage(overall)
	return err
}

// TestPlaintextFinishedRejected is the L8 handshake-level regression: a client
// that sends its Finished as epoch-0 plaintext must be rejected by the server on
// the epoch check (RFC 5246 §7.4.9 / RFC 6347 require the Finished to follow
// ChangeCipherSpec and thus be epoch-1 protected).
func TestPlaintextFinishedRejected(t *testing.T) {
	cfg := func() *Config {
		return &Config{
			PSK:               []byte("a-shared-secret"),
			PSKIdentity:       []byte("ristgo"),
			RetransmitTimeout: 50 * time.Millisecond,
			HandshakeTimeout:  2 * time.Second,
		}
	}
	ca, sa := newPipe()
	client := Client(ca, cfg())
	server := Server(sa, cfg())

	serr := make(chan error, 1)
	go func() { serr <- server.Handshake() }()

	_ = client.plaintextFinishedClientHandshake()
	err := <-serr
	if err == nil {
		t.Fatal("server accepted an epoch-0 plaintext Finished")
	}
	if !strings.Contains(err.Error(), "unprotected") && !strings.Contains(err.Error(), "epoch 0") {
		t.Fatalf("server rejected for the wrong reason: %v", err)
	}
	client.Close()
	server.Close()
}
