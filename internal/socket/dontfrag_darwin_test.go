//go:build darwin

package socket

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestDontFragmentSetDarwin verifies bindNet sets the IP_DONTFRAG socket option on
// macOS: after binding, reading the option back via getsockopt returns a non-zero
// value (the Don't-Fragment bit is on).
func TestDontFragmentSetDarwin(t *testing.T) {
	conn, err := bindNet("udp4", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("bindNet: %v", err)
	}
	defer conn.Close()

	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var (
		val  int
		gerr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		val, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG)
	}); cerr != nil {
		t.Fatalf("Control: %v", cerr)
	}
	if gerr != nil {
		t.Fatalf("getsockopt(IP_DONTFRAG): %v", gerr)
	}
	if val == 0 {
		t.Fatal("IP_DONTFRAG is 0; setDontFragment did not set the Don't-Fragment bit")
	}
}
