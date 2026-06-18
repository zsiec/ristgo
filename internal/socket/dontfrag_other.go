//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package socket

import "net"

// setDontFragment is a no-op on platforms where the Don't-Fragment socket option is
// not wired (e.g. Windows uses IP_DONTFRAGMENT via x/sys/windows). Setting DF is
// best-effort, so a no-op leaves the socket fully usable — datagrams may be
// IP-fragmented by the OS, exactly as before this option existed.
func setDontFragment(_ *net.UDPConn) {}
