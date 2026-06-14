package ristgo_test

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// Dial a receiver and transmit MPEG-TS read from stdin in RTP-sized chunks.
func ExampleDial() {
	tx, err := ristgo.Dial(context.Background(), "203.0.113.7:5000")
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()

	buf := make([]byte, 1316) // 7 MPEG-TS cells per RTP packet
	for {
		n, err := io.ReadFull(os.Stdin, buf)
		if n > 0 {
			if _, werr := tx.Write(buf[:n]); werr != nil {
				log.Fatal(werr)
			}
		}
		if err != nil {
			return
		}
	}
}

// Listen on a port and write the recovered, in-order stream to stdout.
func ExampleListen() {
	rx, err := ristgo.Listen(context.Background(), ":5000")
	if err != nil {
		log.Fatal(err)
	}
	defer rx.Close()

	buf := make([]byte, 4096)
	for {
		n, err := rx.Read(buf)
		if n > 0 {
			os.Stdout.Write(buf[:n])
		}
		if errors.Is(err, ristgo.ErrClosed) || err == io.EOF {
			return
		}
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Dial the Main profile with PSK encryption and a fixed 800 ms recovery buffer.
func ExampleDial_mainProfile() {
	tx, err := ristgo.Dial(context.Background(), "203.0.113.7:5000",
		ristgo.WithProfile(ristgo.ProfileMain),
		ristgo.WithSecret("a-shared-passphrase"),
		ristgo.WithAESKeyBits(256),
		ristgo.WithBuffer(800*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()
}

// Dial the Main profile over a DTLS 1.2 tunnel using a pre-shared key.
func ExampleDial_dtls() {
	tx, err := ristgo.Dial(context.Background(), "203.0.113.7:5000",
		ristgo.WithProfile(ristgo.ProfileMain),
		ristgo.WithDTLS(ristgo.DTLSConfig{PSK: []byte("shared-dtls-key")}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()
}

// Cancelling the context closes the session, aborting a pending handshake and
// unblocking Read/Write.
func ExampleDial_cancellation() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := ristgo.Dial(ctx, "203.0.113.7:5000")
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()
	// When ctx is cancelled (here, after 30 s), tx is closed automatically.
}

// Transmit one flow redundantly over two paths (SMPTE 2022-7 bonding).
func ExampleDialBonded() {
	tx, err := ristgo.DialBonded(context.Background(),
		[]string{"198.51.100.1:5000", "198.51.100.2:5000"})
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()
	tx.Write(make([]byte, 1316))
}

// Receive a bonded flow and deliver the merged, deduplicated stream.
func ExampleListenBonded() {
	rx, err := ristgo.ListenBonded(context.Background(),
		[]string{":5000", ":5002"})
	if err != nil {
		log.Fatal(err)
	}
	defer rx.Close()

	buf := make([]byte, 4096)
	for {
		n, err := rx.Read(buf)
		if n > 0 {
			os.Stdout.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// A receiver that reports link quality back to the sender for source adaptation.
func ExampleListen_sourceAdaptation() {
	rx, err := ristgo.Listen(context.Background(), ":5000",
		ristgo.WithSourceAdaptation())
	if err != nil {
		log.Fatal(err)
	}
	defer rx.Close()
}

// A sender whose encoder retunes to the rate target derived from the receiver's
// link-quality feedback.
func ExampleDial_rateAdapt() {
	tx, err := ristgo.Dial(context.Background(), "203.0.113.7:5000",
		ristgo.WithRateAdapt(func(targetKbps int) {
			log.Printf("retune encoder to %d kbps", targetKbps)
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()
}

// Configure from a full Config struct (the WithConfig escape hatch), useful for
// fields without a dedicated option.
func ExampleWithConfig() {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileAdvanced
	cfg.Secret = "a-shared-passphrase"
	cfg.Compression = true
	cfg.KeyRotation = 100000

	tx, err := ristgo.Dial(context.Background(), "203.0.113.7:5000",
		ristgo.WithConfig(cfg))
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Close()
}

// The Config-based constructor also accepts a rist:// URL whose query parameters
// override the Config.
func ExampleNewReceiver() {
	rx, err := ristgo.NewReceiver("rist://:5000?profile=1&secret=passphrase", ristgo.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}
	defer rx.Close()
}
