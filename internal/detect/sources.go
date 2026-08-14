package detect

import (
	"net/netip"
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

// tracked is per-source detector state that knows when it was last touched.
type tracked interface{ seenAt() time.Time }

// makeRoom forgets sources that have been silent for several detection windows
// and reports whether there is now space for a new one. Callers hold the
// detector's own mutex.
func makeRoom[T tracked](sources map[netip.Addr]T, now time.Time, window time.Duration) bool {
	if len(sources) < maxTrackedSources {
		return true
	}
	if window <= 0 {
		window = time.Minute
	}
	cutoff := now.Add(-idleFactor * window)
	for addr, st := range sources {
		if st.seenAt().Before(cutoff) {
			delete(sources, addr)
		}
	}
	return len(sources) < maxTrackedSources
}
