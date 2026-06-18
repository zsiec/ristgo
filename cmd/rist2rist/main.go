// Command rist2rist is a RIST → RIST relay (libRIST's rist2rist tool). It receives a
// Main-profile RIST stream on the input and re-transmits every recovered packet —
// preserving its sequence and source timestamp — to one or more RIST outputs, so a
// downstream peer recovers an identical flow. It is built on ristgo.Reflect.
//
// The input is a "host:port" or a full "rist://host:port?…" URL (the query knobs —
// profile, secret, buffer, … — configure the whole relay). Each output is a
// "host:port" destination, dialed with the input's configuration.
//
//	rist2rist 'rist://0.0.0.0:5000?secret=hunter2' 203.0.113.5:6000 198.51.100.9:6000
//
// It relays until interrupted (Ctrl-C / SIGTERM).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	ristgo "github.com/zsiec/ristgo"
)

func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rist2rist <input host:port|rist://url> <output host:port> [<output>...]")
		os.Exit(2)
	}
	input, outputs := args[0], args[1:]

	// The reflector is Main-profile; default to it so a bare input addr works (a
	// profile= query knob in the input URL still overrides).
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain

	r, err := ristgo.Reflect(input, outputs, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rist2rist: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "rist2rist: relaying %s -> %d output(s); Ctrl-C to stop\n", input, r.OutputCount())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	if err := r.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "rist2rist: close: %v\n", err)
	}
}
