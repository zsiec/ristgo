// Command bonded-sender transmits stdin redundantly across several RIST receiver
// paths (SMPTE 2022-7 link bonding): every packet is sent on every path, so a
// loss on one path is covered by another's copy with no retransmission. Ctrl-C
// shuts it down cleanly.
//
// Usage:
//
//	bonded-sender 198.51.100.1:5000 198.51.100.2:5000 < in.ts
//
// Each address is a receiver's even media port (RTCP flows on port+1). Pair this
// with a receiver that listens on every path — see DialBonded / ListenBonded.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	ristgo "github.com/zsiec/ristgo"
)

// chunk is the media payload size per RTP packet (7 MPEG-TS cells).
const chunk = 1316

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr> [addr...]\n", os.Args[0])
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tx, err := ristgo.DialBonded(ctx, os.Args[1:], ristgo.WithLogger(ristgo.StdLogger(os.Stderr)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bonded-sender: %v\n", err)
		os.Exit(1)
	}
	defer tx.Close()

	buf := make([]byte, chunk)
	for {
		n, rerr := io.ReadFull(os.Stdin, buf)
		if n > 0 {
			if _, werr := tx.Write(buf[:n]); werr != nil {
				if errors.Is(werr, ristgo.ErrClosed) {
					return // Ctrl-C closed the sender
				}
				fmt.Fprintf(os.Stderr, "bonded-sender: %v\n", werr)
				os.Exit(1)
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return
		}
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "bonded-sender: %v\n", rerr)
			os.Exit(1)
		}
	}
}
