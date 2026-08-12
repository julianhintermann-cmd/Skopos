package api

import (
	"testing"
)

func TestSSEHubPublishAndUnsubscribe(t *testing.T) {
	h := newSSEHub()
	ch1, unsub1 := h.subscribe()
	ch2, unsub2 := h.subscribe()
	if h.count() != 2 {
		t.Fatalf("subscriber count = %d, want 2", h.count())
	}

	h.Publish(Event{Type: "tick", Data: map[string]int{"n": 1}})
	for _, ch := range []chan Event{ch1, ch2} {
		select {
		case e := <-ch:
			if e.Type != "tick" {
				t.Errorf("event type = %q", e.Type)
			}
		default:
			t.Error("subscriber did not receive the published event")
		}
	}

	unsub1()
	if h.count() != 1 {
		t.Errorf("after unsubscribe, count = %d, want 1", h.count())
	}
	unsub2()
	if h.count() != 0 {
		t.Errorf("after all unsubscribed, count = %d, want 0", h.count())
	}
}

func TestSSEHubDropsOnFullBuffer(t *testing.T) {
	h := newSSEHub()
	_, unsub := h.subscribe()
	defer unsub()

	// Publish far more than the buffer without a reader: Publish must never
	// block, silently dropping the overflow.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			h.Publish(Event{Type: "flood", Data: i})
		}
		close(done)
	}()
	<-done // completes only if Publish never blocked
}
