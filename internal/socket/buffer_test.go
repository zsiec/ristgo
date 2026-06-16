package socket

import (
	"net"
	"syscall"
	"testing"
)

// soRcvBuf reads the kernel's SO_RCVBUF for c (Linux reports double the requested
// value; macOS reports the requested value, both clamped to the OS maximum).
func soRcvBuf(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var size int
	var gerr error
	if cerr := raw.Control(func(fd uintptr) {
		size, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); cerr != nil {
		t.Fatalf("Control: %v", cerr)
	}
	if gerr != nil {
		t.Fatalf("GetsockoptInt SO_RCVBUF: %v", gerr)
	}
	return size
}

// TestBindEnlargesReceiveBuffer verifies bindNet requests a larger UDP receive
// buffer than the OS default, so a sender's startup burst is not dropped at the
// kernel (the Linux-only interop stall this guards against). The assertion is
// relative to a default socket, so it holds regardless of the OS's absolute default
// or maximum.
func TestBindEnlargesReceiveBuffer(t *testing.T) {
	deflt, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("default ListenUDP: %v", err)
	}
	defer deflt.Close()

	enlarged, err := bind("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer enlarged.Close()

	d, e := soRcvBuf(t, deflt), soRcvBuf(t, enlarged)
	switch {
	case e < d:
		t.Fatalf("bind SHRANK SO_RCVBUF: default=%d enlarged=%d", d, e)
	case e == d:
		// The OS clamps SO_RCVBUF to its default (rmem_max == rmem_default), so the
		// larger request cannot be honored here; the call still ran without error.
		t.Skipf("OS clamps SO_RCVBUF to the default (%d); cannot verify enlargement", d)
	}
}
