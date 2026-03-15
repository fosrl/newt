package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchBlueprintFile_WriteTriggersSend(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "blueprint-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	go watchBlueprintFile(ctx, f.Name(), func() error {
		calls.Add(1)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(f.Name(), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(700 * time.Millisecond)

	if calls.Load() != 1 {
		t.Errorf("expected 1 send call, got %d", calls.Load())
	}
}

func TestWatchBlueprintFile_DebounceCoalescesEvents(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "blueprint-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	go watchBlueprintFile(ctx, f.Name(), func() error {
		calls.Add(1)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 5; i++ {
		if err := os.WriteFile(f.Name(), []byte("change"), 0644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(700 * time.Millisecond)

	if calls.Load() != 1 {
		t.Errorf("expected 1 send call after debounce, got %d", calls.Load())
	}
}

func TestWatchBlueprintFile_ContextCancellationStops(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "blueprint-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		watchBlueprintFile(ctx, f.Name(), func() error { return nil })
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("watchBlueprintFile did not exit after context cancellation")
	}
}

func TestWatchBlueprintFile_AtomicWriteTriggersSend(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "blueprint.yaml")
	if err := os.WriteFile(target, []byte("initial"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	go watchBlueprintFile(ctx, target, func() error {
		calls.Add(1)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	tmp := filepath.Join(dir, "blueprint.yaml.tmp")
	if err := os.WriteFile(tmp, []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}

	time.Sleep(700 * time.Millisecond)

	if calls.Load() < 1 {
		t.Errorf("expected at least 1 send call after atomic write, got %d", calls.Load())
	}
}

func TestWatchBlueprintFile_MissingFileReturnsGracefully(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watchBlueprintFile(ctx, "/nonexistent/path/blueprint.yaml", func() error { return nil })
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("watchBlueprintFile did not return for missing file")
	}
}
