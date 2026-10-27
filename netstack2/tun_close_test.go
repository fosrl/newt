package netstack2

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
)

// After Close, packets the stack emits must be dropped rather than blocking
// the gVisor goroutine or panicking with "send on closed channel", and Read
// must report os.ErrClosed.
func TestNetTunCloseUnblocksSendersAndReaders(t *testing.T) {
	dev, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.90.0.1")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	tn := dev.(*netTun)

	readErr := make(chan error, 1)
	go func() {
		_, err := tn.Read([][]byte{make([]byte, 1500)}, []int{0}, 0)
		readErr <- err
	}()

	if err := tn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read after Close: got %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after Close")
	}

	sent := make(chan struct{})
	go func() {
		tn.sendIncoming(buffer.NewViewWithData([]byte{0x45}))
		tn.proxyHandler.QueueICMPReply([]byte{0x45})
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("sending a packet after Close blocked")
	}
}
