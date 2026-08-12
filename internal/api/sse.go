package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Event is a server-sent event: a named payload pushed to dashboard clients.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// sseHub is a simple fan-out pub/sub for server-sent events. Each connected
// dashboard holds one subscription; Publish delivers to all of them without
// blocking on a slow client (its buffer drops instead).
type sseHub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func newSSEHub() *sseHub {
	return &sseHub{subs: make(map[chan Event]struct{})}
}

// subscribe registers a new client and returns its channel plus an
// unsubscribe function.
func (h *sseHub) subscribe() (chan Event, func()) {
	ch := make(chan Event, 32)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish delivers e to every subscriber, skipping any whose buffer is full so
// one stalled browser never blocks the pipeline.
func (h *sseHub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
			// Slow consumer: drop this event for them rather than block.
		}
	}
}

// count returns the number of active subscribers (used in tests).
func (h *sseHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// serveSSE streams events to one client until the request is cancelled. It
// writes a periodic comment as a keep-alive so proxies do not time the
// connection out.
func (h *sseHub) serveSSE(w http.ResponseWriter, r *http.Request, keepAlive time.Duration) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := h.subscribe()
	defer unsubscribe()

	ticker := time.NewTicker(keepAlive)
	defer ticker.Stop()

	// Initial comment so the client knows the stream is open.
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			payload, err := json.Marshal(e.Data)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, payload)
			flusher.Flush()
		}
	}
}
