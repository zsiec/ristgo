//go:build interop

package ristgo_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestInteropMainOOBFullIPFromLibrist is the live proof of RIST stream IP
// preservation across implementations. ristgo's Sender connects to a libRIST
// ristreceiver; on authenticating the peer, libRIST sends an out-of-band "api"
// message wrapped in a complete IPv4 packet (tools/oob_shared.c
// oob_build_api_payload: IP protocol 252, ident 54321, then an "auth,..." body),
// framed as GRE FULL. ristgo's ReadOOB recovers that whole IP packet, headers
// and all, byte-for-byte, proving the two implementations share the full-IP
// out-of-band wire format.
func TestInteropMainOOBFullIPFromLibrist(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	rxPort := freeMainPort(t)
	capPort := freeUDPPort(t, rxPort)

	// libRIST receiver (PSK Main, the authenticator). It sends its OOB api
	// message once it authenticates ristgo. Media is discarded to capPort.
	newUDPCapture(t, capPort, interopN*interopChunk)
	spawnTool(t, receiver, "-p", "1", "-s", mainInteropSecret, "-e", "256", "-b", "1000",
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	waitToolReady(t, rxPort, 5*time.Second)

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), mainInteropConfig(256))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	// Stream media so the receiver authenticates us and fires its OOB-on-connect.
	stop := make(chan struct{})
	go func() {
		chunk := make([]byte, interopChunk)
		tx.SetWriteDeadline(time.Now().Add(30 * time.Second))
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, werr := tx.Write(chunk); werr != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	defer close(stop)

	type oobResult struct {
		data []byte
		err  error
	}
	res := make(chan oobResult, 1)
	go func() {
		buf := make([]byte, 4096)
		n, rerr := tx.ReadOOB(buf)
		res <- oobResult{append([]byte(nil), buf[:n]...), rerr}
	}()

	var oob []byte
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("ReadOOB: %v", r.err)
		}
		oob = r.data
	case <-time.After(20 * time.Second):
		t.Fatal("no OOB received from the libRIST receiver within 20s")
	}

	// The recovered datagram must be libRIST's complete IPv4 api packet.
	if len(oob) < 20 || oob[0] != 0x45 {
		t.Fatalf("OOB is not an IPv4 packet (len=%d): % x", len(oob), oob)
	}
	if oob[9] != 252 { // RIST_OOB_API_IP_PROTOCOL
		t.Fatalf("IP protocol = %d, want 252 (RIST_OOB_API_IP_PROTOCOL)", oob[9])
	}
	if id := binary.BigEndian.Uint16(oob[4:6]); id != 54321 { // RIST_OOB_API_IP_IDENT_AUTH
		t.Fatalf("IP ident = %d, want 54321 (RIST_OOB_API_IP_IDENT_AUTH)", id)
	}
	if totalLen := binary.BigEndian.Uint16(oob[2:4]); int(totalLen) != len(oob) {
		t.Fatalf("IP total length field = %d, but datagram is %d bytes (header not preserved)", totalLen, len(oob))
	}
	if !bytes.Contains(oob[20:], []byte("auth,")) {
		t.Fatalf("OOB payload missing libRIST's auth message: %q", oob[20:])
	}
	t.Logf("ristgo recovered libRIST's OOB IP packet byte-exact: %d bytes, proto=252 ident=54321 msg=%q",
		len(oob), oob[20:])
}
