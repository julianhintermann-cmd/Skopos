package detect

import (
	"testing"
	"time"
)

// The window slides: events older than the window stop counting, so a source
// that stays just under the limit forever never fires.
func TestRateWindowSlides(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var w rateWindow
	const window = 10 * time.Second

	// 100 events spread over the first second.
	for i := 0; i < 100; i++ {
		w.add(base.Add(time.Duration(i)*10*time.Millisecond), window, 1)
	}
	if got := w.add(base.Add(time.Second), window, 0); got != 100 {
		t.Errorf("total inside the window = %d, want 100", got)
	}
	// Eleven seconds later everything has aged out.
	if got := w.add(base.Add(11*time.Second), window, 0); got != 0 {
		t.Errorf("total after the window passed = %d, want 0", got)
	}
	// A long idle gap resets rather than looping the ring.
	w.add(base.Add(time.Hour), window, 5)
	if got := w.add(base.Add(time.Hour), window, 0); got != 5 {
		t.Errorf("total after an idle hour = %d, want 5", got)
	}
}

// Counting is constant-memory: the old implementation kept one timestamp per
// packet, which at the shipped defaults meant eighty thousand per source.
func TestRateWindowIsConstantSize(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var w rateWindow
	const window = 10 * time.Second
	for i := 0; i < 200000; i++ {
		w.add(base.Add(time.Duration(i)*time.Microsecond), window, 1)
	}
	if len(w.counts) != rateBuckets {
		t.Errorf("bucket count = %d, want the fixed %d", len(w.counts), rateBuckets)
	}
	if w.total <= 0 || w.total > 200000 {
		t.Errorf("total = %d, want a plausible in-window count", w.total)
	}
}

func BenchmarkRateWindowAdd(b *testing.B) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var w rateWindow
	for i := 0; i < b.N; i++ {
		w.add(base.Add(time.Duration(i)*time.Microsecond), 10*time.Second, 1)
	}
}
