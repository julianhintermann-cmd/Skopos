package detect

// maxTrackedSources bounds the per-source state every detector keeps.
//
// An internet-facing box sees a steady trickle of unique scanning addresses,
// and each one used to earn a permanent map entry. The entries are small now,
// so this is a slow leak rather than a sharp one — but a process that runs for
// months has no upper bound on how many distinct addresses knock on it, and a
// monitoring tool that eventually exhausts memory has stopped monitoring.
//
// Past the cap, new sources are simply not tracked. That is the right way
// round: the addresses already on record are the ones actively misbehaving,
// and forgetting them to make room for a fresh one would be exactly what a
// flood of spoofed sources wants.
const maxTrackedSources = 8192
