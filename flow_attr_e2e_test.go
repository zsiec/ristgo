package ristgo_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EAdvFlowAttribute exercises the full Advanced-profile flow-attribute
// feature end to end in pure Go: a sender calls WriteFlowAttribute with a JSON
// body, and the receiver's OnFlowAttr callback fires with the exact bytes. It
// proves the whole path — Sender.WriteFlowAttribute -> session flowAttrIn ->
// sendFlowAttr (CI 0x8001 control datagram) -> the Advanced codec decode ->
// wire.FlowAttribute -> feedFeedback interception -> Config.OnFlowAttr — agrees
// with itself; the interop test proves the wire format agrees with libRIST.
func TestE2EAdvFlowAttribute(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	got := make(chan []byte, 8)
	rxCfg := advConfig("", 0, false)
	rxCfg.OnFlowAttr = func(json []byte) {
		// The slice is valid only for the call; copy it out. Non-blocking so the
		// event loop is never stalled by the callback.
		cp := append([]byte(nil), json...)
		select {
		case got <- cp:
		default:
		}
	}
	rx, err := ristgo.NewReceiver(addr, rxCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	tx, err := ristgo.NewSender(addr, advConfig("", 0, false))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	want := []byte(`{"session":"ristgo","profile":"advanced","flow_id":1968,"k":"v"}`)

	// Drain delivered media so the receiver's pipeline runs (and the session stays
	// healthy) while we wait for a flow attribute.
	go func() {
		buf := make([]byte, 4096)
		rx.SetReadDeadline(time.Now().Add(12 * time.Second))
		for {
			if _, rerr := rx.Read(buf); rerr != nil {
				return
			}
		}
	}()

	// Stream a little media to establish the peer (WriteFlowAttribute is dropped
	// until the receiver's return address is learned), then send flow attributes
	// repeatedly until one is observed.
	done := make(chan struct{})
	go func() {
		defer close(done)
		tx.SetWriteDeadline(time.Now().Add(12 * time.Second))
		media := make([]byte, 1316)
		for i := 0; i < 600; i++ {
			if _, werr := tx.Write(media); werr != nil {
				return
			}
			if i%10 == 0 {
				if ferr := tx.WriteFlowAttribute(want); ferr != nil {
					t.Errorf("WriteFlowAttribute: %v", ferr)
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
			select {
			case <-done:
				return
			default:
			}
		}
	}()

	select {
	case j := <-got:
		if string(j) != string(want) {
			t.Fatalf("OnFlowAttr got %q, want %q", j, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnFlowAttr never fired")
	}
}

// TestE2EFlowAttributeUnsupportedProfile verifies WriteFlowAttribute is rejected
// on a non-Advanced sender (flow attributes are Advanced-only) and that OnFlowAttr
// is rejected at construction on a non-Advanced receiver.
func TestE2EFlowAttributeUnsupportedProfile(t *testing.T) {
	// Simple sender: no flow-attribute channel.
	stx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", freeEvenPort(t)), ristgo.DefaultConfig())
	if err != nil {
		t.Fatalf("NewSender(Simple): %v", err)
	}
	defer stx.Close()
	if err := stx.WriteFlowAttribute([]byte("{}")); !errors.Is(err, ristgo.ErrFlowAttrUnsupported) {
		t.Fatalf("Simple WriteFlowAttribute = %v, want ErrFlowAttrUnsupported", err)
	}

	// Main sender: also no flow-attribute channel.
	mtx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", freeMainPort(t)), mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewSender(Main): %v", err)
	}
	defer mtx.Close()
	if err := mtx.WriteFlowAttribute([]byte("{}")); !errors.Is(err, ristgo.ErrFlowAttrUnsupported) {
		t.Fatalf("Main WriteFlowAttribute = %v, want ErrFlowAttrUnsupported", err)
	}

	// OnFlowAttr on a non-Advanced receiver is a config error.
	badCfg := mainConfig("", 0)
	badCfg.OnFlowAttr = func([]byte) {}
	if rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", freeMainPort(t)), badCfg); err == nil {
		rx.Close()
		t.Fatal("NewReceiver accepted OnFlowAttr on a Main-profile config")
	}
}
