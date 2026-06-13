package socket

import (
	"net"
	"testing"
	"time"
)

func TestListenRejectsBadPort(t *testing.T) {
	for _, port := range []int{0, 5001, -2} {
		if c, err := Listen("127.0.0.1", port); err == nil {
			c.Close()
			t.Errorf("Listen(port=%d) succeeded, want error (port must be positive even)", port)
		}
	}
}

func TestListenBindsPair(t *testing.T) {
	c, err := Listen("127.0.0.1", 0+evenProbe(t))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer c.Close()
	if c.MediaPort()%2 != 0 {
		t.Fatalf("media port %d is not even", c.MediaPort())
	}
}

// evenProbe finds a free even port whose successor is also free.
func evenProbe(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		p, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			continue
		}
		port := p.LocalAddr().(*net.UDPAddr).Port
		p.Close()
		if port%2 != 0 {
			port--
		}
		c, err := Listen("127.0.0.1", port)
		if err != nil {
			continue
		}
		c.Close()
		return port
	}
	t.Fatal("no free even port")
	return 0
}

func TestMediaAndRTCPRoundTrip(t *testing.T) {
	port := evenProbe(t)
	rx, err := Listen("127.0.0.1", port)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer rx.Close()
	tx, err := ListenEphemeral("127.0.0.1")
	if err != nil {
		t.Fatalf("ListenEphemeral: %v", err)
	}
	defer tx.Close()

	mediaDst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	rtcpDst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port + 1}

	if err := tx.WriteMedia([]byte("media"), mediaDst); err != nil {
		t.Fatalf("WriteMedia: %v", err)
	}
	if err := tx.WriteRTCP([]byte("rtcp"), rtcpDst); err != nil {
		t.Fatalf("WriteRTCP: %v", err)
	}

	rx.media.SetReadDeadline(time.Now().Add(time.Second))
	rx.rtcp.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 64)
	n, src, err := rx.ReadMedia(buf)
	if err != nil || string(buf[:n]) != "media" {
		t.Fatalf("ReadMedia = %q, %v, %v", buf[:n], src, err)
	}
	if src == nil {
		t.Fatal("ReadMedia returned nil source address")
	}
	n, _, err = rx.ReadRTCP(buf)
	if err != nil || string(buf[:n]) != "rtcp" {
		t.Fatalf("ReadRTCP = %q, %v", buf[:n], err)
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	c, err := Listen("127.0.0.1", evenProbe(t))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.ReadMedia(make([]byte, 64))
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	c.Close()
	select {
	case <-errc: // returned (closed) — good
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock a pending ReadMedia")
	}
}
