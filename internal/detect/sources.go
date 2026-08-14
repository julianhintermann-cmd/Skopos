package detect

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// maxTrackedSources bounds the per-source state every detector keeps.
//
// An internet-facing box sees a steady trickle of unique scanning addresses,
// and each one used to earn a permanent map entry. The entries are small now,
// so this is a slow leak rather than a sharp one — but a process that runs for
// months has no upper bound on how many distinct addresses knock on it, and a
// monitoring tool that eventually exhausts memory has stopped monitoring.
//
// Past the cap, room is made by forgetting sources that have gone quiet, and
// only if that frees nothing is the new source dropped. That ordering matters
// in both directions. Never forgetting anything was the worse failure: the cap
// was reached in days to weeks on a port-forwarded box, and from then on every
// genuinely new source — including whoever was attacking at that moment — was
// silently untracked, with the map full of addresses last heard from weeks
// earlier. The detector went deaf and nothing said so. Conversely, evicting
// active entries to make room is exactly what a flood of spoofed sources
// wants, so entries still inside the detection window are never touched.
const maxTrackedSources = 8192

// idleFactor sets how long past the detection window a source must be silent
// before its state can be reclaimed. A source seen within the window is still
// under evaluation; a few windows of silence means it has stopped.
const idleFactor = 4

// ShedStats reports what a detector's bounded state has had to give up, from
// start. Both numbers are ordinarily zero.
//
// Every bound in this package reports what it costs. A cap that discards in
// silence is how the baseline detector spent months refusing to learn any new
// device with nothing in the logs, in a metric or on the System view to say
// so — the operator saw a detector that was running and assumed it was
// watching. Nothing here is allowed to fail that quietly again.
type ShedStats struct {
	// Forgotten counts per-source state reclaimed to stay inside the bound.
	// A steady trickle is the bound working as intended.
	Forgotten uint64
	// Untracked counts sources the detector declined to take on at all,
	// because the map was full of entries still under evaluation. Non-zero
	// means the detector is not watching everything it can see.
	Untracked uint64
}

// shed accumulates ShedStats. Detectors update it on the packet path under
// their own mutex and it is read from HTTP handlers, hence the atomics.
type shed struct {
	forgotten atomic.Uint64
	untracked atomic.Uint64
}

func (s *shed) stats() ShedStats {
	return ShedStats{Forgotten: s.forgotten.Load(), Untracked: s.untracked.Load()}
}

// tracked is per-source detector state that knows when it was last touched.
type tracked interface{ seenAt() time.Time }

// makeRoom forgets sources that have been silent for several detection windows
// and reports whether there is now space for a new one. Callers hold the
// detector's own mutex. Whatever it gives up — reclaimed entries, or the new
// source it could not fit — is counted into sh.
func makeRoom[T tracked](sources map[netip.Addr]T, now time.Time, window time.Duration, sh *shed) bool {
	if len(sources) < maxTrackedSources {
		return true
	}
	if window <= 0 {
		window = time.Minute
	}
	cutoff := now.Add(-idleFactor * window)
	before := len(sources)
	for addr, st := range sources {
		if st.seenAt().Before(cutoff) {
			delete(sources, addr)
		}
	}
	sh.forgotten.Add(uint64(before - len(sources)))
	if len(sources) < maxTrackedSources {
		return true
	}
	sh.untracked.Add(1)
	return false
}
