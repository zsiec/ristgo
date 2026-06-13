// Command sender is a minimal RIST sender example: it reads media from stdin
// and transmits it to a RIST receiver.
//
// Usage:
//
//	sender 'rist://127.0.0.1:5000?profile=0&buffer=1000' < in.ts
//	ffmpeg ... -f mpegts - | sender 127.0.0.1:5000
//
// The address is the receiver's even media port; RTCP flows on port+1.
package main

import (
	"fmt"
	"io"
	"os"

	ristgo "github.com/zsiec/ristgo"
)

// chunk is the media payload size per RTP packet (7 MPEG-TS cells).
const chunk = 1316

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr|rist://url>\n", os.Args[0])
		os.Exit(2)
	}
	cfg := ristgo.DefaultConfig()
	cfg.Logger = ristgo.StdLogger(os.Stderr)

	tx, err := ristgo.NewSender(os.Args[1], cfg)
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
