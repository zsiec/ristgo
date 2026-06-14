// Command sender is a minimal RIST sender example: it reads media from stdin and
// transmits it to a RIST receiver. Ctrl-C shuts it down cleanly.
//
// Usage:
//
//	sender '203.0.113.7:5000' < in.ts
//	ffmpeg ... -f mpegts - | sender 'rist://203.0.113.7:5000?profile=1&secret=passphrase'
//
// The address is the receiver's even media port (RTCP flows on port+1) for the
// Simple profile, or the single port for Main/Advanced. Query parameters on a
// rist:// URL override the defaults.
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
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr|rist://url>\n", os.Args[0])
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tx, err := ristgo.Dial(ctx, os.Args[1], ristgo.WithLogger(ristgo.StdLogger(os.Stderr)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sender: %v\n", err)
		os.Exit(1)
	}
	defer tx.Close()

	// Copy stdin to the sender in RTP-sized chunks.
	buf := make([]byte, chunk)
	for {
		n, rerr := io.ReadFull(os.Stdin, buf)
		if n > 0 {
			if _, werr := tx.Write(buf[:n]); werr != nil {
				if errors.Is(werr, ristgo.ErrClosed) {
					return // Ctrl-C closed the sender
				}
				fmt.Fprintf(os.Stderr, "sender: %v\n", werr)
				os.Exit(1)
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return
		}
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "sender: %v\n", rerr)
			os.Exit(1)
		}
	}
}
