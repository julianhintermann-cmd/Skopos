import { APIError } from '../lib/api'

// humanError turns what the server said into what a person needs to hear.
//
// The firewall's errors are precise and are written for a log: "the firewall
// rejected the change; the block is still in place", and underneath that a
// netlink complaint like "file exists". Both are true. Neither tells someone
// holding a phone whether the address they just tried to block is blocked, and
// the raw kernel text in particular reads as a crash rather than as a refusal
// the firewall made deliberately — which is how the EEXIST toast became a bug
// report about Skopos being broken when Skopos was in fact protecting itself.
//
// Each case says what happened and what is true now. The second half is the
// part that matters: an error message that leaves the reader unsure whether
// their network is protected has failed at its job.
export function humanError(err: unknown, action: 'block' | 'unblock' | 'apply' = 'apply'): string {
  const raw = err instanceof Error ? err.message : String(err)
  const lower = raw.toLowerCase()
  const status = err instanceof APIError ? err.status : 0

  if (lower.includes('never-block allowlist') || lower.includes('allowlist')) {
    return 'That address is on the never-block list, along with your gateway. Nothing was changed — blocking it would cut this machine off the network.'
  }
  if (lower.includes('whole address family')) {
    return 'Refused: that would block every address there is, including the one you are reading this from. Nothing was changed.'
  }
  if (lower.includes('still in place')) {
    return 'The firewall would not lift it, so the block is still in place. The list still shows it because it is still real.'
  }
  if (lower.includes('nothing was blocked') || lower.includes('not enforced')) {
    return 'The firewall rejected the rule, so nothing was blocked. The entry was rolled back rather than left listing an address the kernel never had.'
  }
  // The kernel refuses overlapping ranges. Before 0.3.3 this surfaced verbatim
  // and looked like a fault; it is a refusal with a cause worth naming.
  if (lower.includes('file exists') || lower.includes('eexist')) {
    return 'That range overlaps one already blocked. The kernel will not hold two overlapping ranges, so nothing was changed — block the wider range instead, or lift the existing one first.'
  }
  // 202 travels as an error on purpose: the server stored the change and the
  // kernel refused it. Both halves have to be said, because "it did not work"
  // would send someone to re-enter a setting that is already saved, and "saved"
  // alone would leave them believing it is in force.
  if (status === 202) {
    return `Saved, but the firewall did not take it: ${raw}. The setting is stored and is not in effect.`
  }
  if (status === 409) {
    return `Conflict: ${raw}. Nothing was changed.`
  }
  if (status === 401 || status === 403) {
    return 'Not permitted. Nothing was changed.'
  }
  if (status >= 500 || status === 0) {
    const what =
      action === 'block' ? 'block' : action === 'unblock' ? 'lift the block' : 'apply the change'
    // Deliberately does not guess. A failed request may have been applied
    // before the connection dropped, and claiming either way would be
    // inventing an outcome nobody observed.
    return `Could not ${what} — the server did not answer. Reload to see the current state before trying again.`
  }
  return raw
}
