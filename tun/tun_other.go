//go:build !linux && !darwin

package tun

// Open returns ErrUnsupported on platforms without a TUN implementation (everything
// but Linux and macOS — libRIST's Windows TUN is itself an unimplemented stub).
func Open(requestedName string) (*Device, error) { return nil, ErrUnsupported }

// Read is unsupported on this platform.
func (d *Device) Read(p []byte) (int, error) { return 0, ErrUnsupported }

// Write is unsupported on this platform.
func (d *Device) Write(p []byte) (int, error) { return 0, ErrUnsupported }

// Close is a no-op on this platform (no device is ever opened).
func (d *Device) Close() error { return nil }

// SetIP is unsupported on this platform.
func SetIP(dev, ip string, prefixLen int) error { return ErrUnsupported }

// SetMTU is unsupported on this platform.
func SetMTU(dev string, mtu int) error { return ErrUnsupported }

// BringUp is unsupported on this platform.
func BringUp(dev string) error { return ErrUnsupported }
