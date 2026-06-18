package ristgo_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2ERecvBlock verifies per-packet block delivery (libRIST rist_receiver_data_block):
// Receiver.RecvBlock yields each recovered packet as a DataBlock carrying its sequence,
// source timestamp, and the virtual ports decoded from the Main GRE reduced-overhead
// header — proving per-packet metadata flows decode → core → app.
func TestE2ERecvBlock(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	recvCfg := mainConfig("", 0)
	recvCfg.BlockDelivery = true
	recvCfg.VirtSrcPort = 5000
	recvCfg.VirtDstPort = 6000
	recvCfg.BufferMin = 150 * time.Millisecond
	recvCfg.BufferMax = 150 * time.Millisecond

	sendCfg := mainConfig("", 0)
	sendCfg.VirtSrcPort = 5000
	sendCfg.VirtDstPort = 6000

	rx, err := ristgo.NewReceiver(addr, recvCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, sendCfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	const n = 40
	mk := func(i int) []byte { return []byte(fmt.Sprintf("block-%04d", i)) }
	go func() {
		tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
		for i := 0; i < n+8; i++ {
			if _, err := tx.Write(mk(i)); err != nil {
				return
			}
			time.Sleep(3 * time.Millisecond)
		}
	}()

	var prevSeq uint32
	var havePrev bool
	for i := 0; i < n; i++ {
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		blk, err := rx.RecvBlock()
		if err != nil {
			t.Fatalf("RecvBlock at %d: %v", i, err)
		}
		if string(blk.Payload) != string(mk(i)) {
			t.Fatalf("block %d payload = %q, want %q", i, blk.Payload, mk(i))
		}
		if blk.VirtSrcPort != 5000 || blk.VirtDstPort != 6000 {
			t.Fatalf("block %d virt ports = %d/%d, want 5000/6000", i, blk.VirtSrcPort, blk.VirtDstPort)
		}
		if blk.SourceTime == 0 {
			t.Fatalf("block %d has no source timestamp", i)
		}
		if havePrev && blk.Seq != prevSeq+1 {
			t.Fatalf("block %d seq %d not contiguous after %d", i, blk.Seq, prevSeq)
		}
		prevSeq, havePrev = blk.Seq, true
	}

	// Read is unavailable on a block-delivery receiver.
	if _, err := rx.Read(make([]byte, 1316)); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("Read on a block receiver = %v, want ErrInvalidConfig", err)
	}
}

// TestRecvBlockRejectedWithoutBlockDelivery checks RecvBlock errors on a plain receiver.
func TestRecvBlockRejectedWithoutBlockDelivery(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rx, err := ristgo.NewReceiver(addr, mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	if _, err := rx.RecvBlock(); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("RecvBlock without BlockDelivery = %v, want ErrInvalidConfig", err)
	}
}

// TestBlockDeliveryRejectedOffMain checks validation gates BlockDelivery to Main.
func TestBlockDeliveryRejectedOffMain(t *testing.T) {
	cfg := advConfig("", 0, false)
	cfg.BlockDelivery = true
	if _, err := ristgo.NewReceiver("127.0.0.1:0", cfg); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("BlockDelivery off Main = %v, want ErrInvalidConfig", err)
	}
}
