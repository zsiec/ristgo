//go:build interop

// Advanced-profile flow-attribute (TR-06-3 §5.3.7) interop test. libRIST's
// Advanced sender emits a Flow Attribute control message (CI 0x8001) roughly once
// per second once Advanced is negotiated, carrying a JSON metadata body. This
// proves ristgo's OnFlowAttr receive path decodes libRIST's flow attribute and
// surfaces its JSON to the application. (The ristgo -> libRIST send direction is
// covered by the Go<->Go e2e round trip and the BuildFlowAttr wire-format unit
// test; the libRIST ristreceiver tool registers no flow-attr callback, so that
// direction is not observable through the CLI.)
package ristgo_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestInteropAdvFlowAttrGoRxFromLibristTx: libRIST ristsender (-p 2) -> ristgo
// Advanced Receiver with OnFlowAttr. The callback must fire with the JSON body
// libRIST announces (which includes "profile":"advanced").
func TestInteropAdvFlowAttrGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedPort := freeUDPPort(t, goPort)

	got := make(chan []byte, 8)
	cfg := advInteropConfig(0, false) // cleartext Advanced
	cfg.OnFlowAttr = func(json []byte) {
		cp := append([]byte(nil), json...)
		select {
		case got <- cp:
		default:
		}
	}
	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	args := append(advToolArgs(0),
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	spawnTool(t, sender, args...)
	waitToolReady(t, feedPort, 5*time.Second)

	// Keep a light media trickle flowing so both sessions stay established for the
	// few seconds libRIST needs to fire its ~1Hz flow-attribute timer.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		c, derr := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: feedPort})
		if derr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, interopChunk)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				c.Write(buf)
			}
		}
	}()

	// Drain delivered media so the receiver pipeline runs.
	go func() {
		b := make([]byte, 4096)
		rx.SetReadDeadline(time.Now().Add(12 * time.Second))
		for {
			if _, rerr := rx.Read(b); rerr != nil {
				return
			}
		}
	}()

	select {
	case j := <-got:
		// libRIST's minimal schema includes "profile":"advanced"; assert it is a
		// non-empty JSON object carrying that, proving the body decoded intact.
		if len(j) == 0 || j[0] != '{' || !bytes.Contains(j, []byte("advanced")) {
			t.Fatalf("OnFlowAttr fired with unexpected body: %q", j)
		}
		t.Logf("received libRIST flow attribute (%d bytes): %s", len(j), j)
	case <-time.After(10 * time.Second):
		t.Fatal("OnFlowAttr never fired — no flow attribute received from libRIST")
	}
}
