# Changelog

All notable changes to Skopos are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0]

Practically every address an operator opened reported "Abuse 70%". The
figure was a constant. A match against any subscribed blocklist was
hardcoded to 70, `combine` took the maximum across sources, and the built-in
lists cover enough address space that almost anything worth looking at is on
one — so the reading was 70, then 70 again, for unrelated addresses with
nothing in common.

The rest of that scale was no better. Twenty blocklist.de reports became 70,
a hundred became 85, five DShield reports became 15. None of these sources
publishes a risk rating; they publish counts and memberships. When AbuseIPDB
was dropped in 0.3.0 its genuine abuse-confidence score went with it, the
field on the card stayed, and the gap was filled by bucketing report counts
into numbers that look measured and are not.

There is no score now, and there will not be one: no free keyless source
publishes a defined scale, and the available quantities are not
commensurable — a DShield record count, a fail2ban report inside a 24-hour
window and a blocklist membership do not share an axis, and the weights that
would put them on one would come from Skopos rather than from anybody's
measurement. Each source's own answer is reported with the counts that source
published, and the summary is a word.

### Added

- **An AI integration, configured entirely in the web UI.** Pick OpenAI,
  Anthropic or OpenRouter from a dropdown, then enter a key; it is verified
  with the provider before anything is written, sealed with the same AES-GCM
  box that holds the Cloudflare token, and returned by no endpoint. The
  service interface has no method that yields a key, so the HTTP layer has no
  way to ask for one. Nothing is configured from YAML, because a secret in a
  YAML file is a secret in a backup and in a screenshot.
- **"Explain this alert"** turns one finding into one paragraph. It is a
  button, never a poll and never a page load: every request traces to a
  click, which bounds the cost, keeps the exposure legible to the person who
  caused it, and makes a failure a visible error rather than a silent nightly
  leak. The answer arrives with the exact payload that was sent, so "what
  leaves this machine" is something the operator can read rather than a claim
  in a settings page.
- **A redaction layer with its own tests**, because this is the single
  exception to the README's promise that captured data never leaves the NAS.
  Addresses are reduced to a shape (`192.168.1.x`) — external ones too, since
  the final octet adds nothing to an explanation and a public address is one
  join from an identity. Devices are numbered rather than named. MAC
  addresses, operator-typed labels and DHCP hostnames are never sent: they
  identify people, and a home network carries the browsing of a household
  that never agreed to any of this. A guard re-reads the finished payload and
  refuses to send if a banned shape survived.
- **A motion layer.** Five durations and three curves, Carbon's productive
  set — it exists for dense operational screens and pairs with the IBM Plex
  already shipped. Redefining two Tailwind defaults retuned all 22 existing
  transition sites without touching a component.
- **Row hover on all five tables.** There was none anywhere in the app; every
  hover rule in it was on a button or a link, while the token for this already
  existed and went unused. On a seven-column flow table, tracking one row
  across the width is the most common thing an operator does.
- **`GET/POST/PATCH/DELETE /api/integrations/ai`** and **`POST
  /api/integrations/ai/explain`**, and a `Store.Alert` lookup by id — the
  detail pages previously found their alert by scanning the most recent page,
  so an older one rendered as "not on this page" while the row sat in the
  table.

### Changed

- **The reputation card reports evidence instead of a number.** One row per
  source, always present, including the ones that had nothing and the ones
  that failed — a source missing from the card is indistinguishable from one
  that answered "nothing here", and telling those apart is the panel's whole
  job. The verdict is `listed`, `reported`, `no_reports` or `unknown`, and
  none of them is green: two sensor networks not having heard of an address is
  a weak statement about a large internet, so it stays labelled "checked, not
  cleared".
- **A blocklist match names the list, and says what the list is.** "On a
  blocklist" leaves the reader unable to weigh the match. Naming it exposed a
  second problem: FireHOL Level 1 already contains Spamhaus DROP, so an
  address on DROP rendered as two lists agreeing when it was one fact —
  contained lists now collapse into their container. And roughly 97% of
  FireHOL Level 1's address space is unallocated bogons rather than observed
  attackers, so the card prints that beside the name instead of letting the
  name imply a confirmed attacker.
- **Reduced motion now reduces rather than removes.** The blanket rule
  flattened every duration to 0.01ms, which also flattened the row-arrival
  tint — the one animation here carrying information rather than polish — so
  a reduced-motion operator lost the only signal that a row was new.
  Entrances keep the fade and lose the travel, the row mark survives at
  interaction speed, looping stops. The rule also gains
  `animation-iteration-count`, which it was missing: without it an `infinite`
  animation kept looping at 0.01ms a cycle, a permanent compositor wake-up
  rather than a stopped animation.
- **The bottom sheet, the live dot, the button spinner and the row flash**
  are tokens rather than four hard-coded duration strings in three notations.

### Fixed

- **The input border failed WCAG 1.4.11.** `--sk-line-strong` measured
  2.14:1 against the field it outlines in light and 2.40:1 in dark; a
  control's visual boundary needs 3:1. Both now clear it. The no-data hatch
  was 1.57:1 while carrying meaning — "no reading here" — and is fixed the
  same way.
- **The skeleton shimmer was invisible.** It swept between two colours 1.08:1
  apart on a base 1.16:1 from the card behind it: a 1.4s infinite compositor
  animation running where nobody could see it. It now has an amplitude.
- **A source that could not be reached is no longer silent.** Every
  reputation source leaves a signal behind when it fails, so "could not be
  reached" and "answered, had nothing" are visibly different. That changed
  what "every source failed" means, so the check now asks whether any source
  produced a reading rather than whether any signal exists.
- **Feed matches on reserved address space** — `0.0.0.0/8`, IETF protocol
  assignments, benchmarking space and `240.0.0.0/4` — no longer count. A
  packet from one of those is spoofed or misrouted, which is worth nothing as
  a reputation signal and plenty as noise.

### Upgrading

- **No migration runs.** The AI key and its settings live in the existing
  `meta` key-value table, so 0.5.0 starts against a 0.4.0 database unchanged.
- **API consumers:** `/api/reputation` no longer returns `abuse_score`. It
  returns `verdict` (`listed` / `reported` / `no_reports` / `unknown`) and a
  `signals` array in which each entry carries `state`, `detail`, and the
  `reports` / `targets` / `lists` that source actually published. A client
  reading `abuse_score` gets nothing; there is no compatibility shim, because
  emitting the old field would mean continuing to compute the number this
  release exists to remove.
- **The AI integration is off until you turn it on**, and storing a key does
  not turn it on — sending household data to a third party is a separate,
  explicit decision, taken after the disclosure on the settings card. With it
  off, no request is made to any provider, including a test one.

## [0.4.0]

Three hours with the capture down came out of the throughput chart as a clean
straight line. `store/query.go` said in its own doc comment that empty buckets
are omitted and "the caller fills gaps for charting". No caller ever did, and
the chart joins consecutive points, so the most confident-looking thing on the
page was the part nobody had measured.

Underneath it sat a second untruth. Adaptive sampling drops packets before the
aggregator and the aggregator summed what reached it, so at keep rate 0.1 every
stored byte was a tenth of the traffic, written into the rollups as a total and
kept there for as long as the rollups are. Sampling engages during a flood, so
an attack rendered as a dip — the numbers were least reliable at the moment
they were worth reading.

Most of this release is the work of letting a screen say "I do not know".
Buckets now record what the capture was doing while they were filled, so a
quiet network and a dead one stop leaving identical rows. Charts break the line
where nothing was measured. Tiles and endpoints omit a figure they could not
fetch instead of printing a zero. Enforcement is reported from what the kernel
was last found to hold rather than from the configuration that asked for it,
and that reading now expires — the check added in 0.3.3 recorded a pass and
kept it forever, so a verify goroutine that died left every screen reporting
protection from a reading days old.

Two things a stranger could reach are closed. Later IPv4 fragments were read as
though they carried a transport header, so anyone able to send fragments to
this host chose which addresses appeared to be opening connections — and a
detector finding carries a block suggestion. And `X-Forwarded-For` was believed
no matter who sent it, which let one attacker present a new address on every
request and kept the login rate limiter from ever counting to two.

### Added

- **Buckets record what the capture was doing, not just what it saw.**
  Migration 0010 adds coverage tables beside the three rollups: how many
  capture sources were configured and how many were up, how many seconds of the
  bucket a heartbeat covered, and the packet count before and after sampling.
  Coverage is written on a heartbeat rather than on arrival, which is the whole
  point — a record that appears only when packets do cannot tell silence from
  absence. Capture status is asserted by the goroutines owning the sources
  (`starting`, `up`, `partial`, `down`), never inferred from a quiet minute.
- **Every chart point now says what its numbers mean.** A bucket is `measured`
  (capture up, nothing sampled, the figures are exact), `sampled` (a keep rate
  below 1, an interface missing, or only part of the bucket covered — the byte
  counts are a floor and the keep rate says what fraction they came from),
  `down` (capture not running, no measurement exists), `nodata` (outside
  recorded history) or `unverified` (recorded before this release: numbers
  present, completeness unstated). Series are dense rather than sparse, and a
  per-series summary counts each state so a view can say "27 of 877 minutes not
  captured" without walking the array.
- **Sampled buckets are drawn as two lines and a band.** Solid is what was
  counted, exact as a lower bound; dashed is measured divided by the keep rate,
  which is an estimate and not a ceiling; the space between them is the part
  nobody can resolve. The stored value is never scaled up — an estimate shaped
  like a measurement is the thing this release exists to stop — and the tooltip
  says "1 in 10 packets kept" rather than leaving the reader to infer it. Bucket
  packet
  totals are exact even under sampling, because the sampler counts before it
  drops.
- **Upload and download are separate numbers.** Every raw flow has carried
  `out_bytes` since the first migration; the writer added the two halves
  together, so the split survived only as long as the seven-day raw window and
  no screen could tell a camera uploading four gigabytes overnight from an
  evening of streaming. Migration 0011 adds the column to all three rollups.
  On a device series the two halves always sum to the total; on the
  network-wide series traffic that never crossed the boundary belongs to
  neither half and the remainder is that local and transit traffic, not a
  rounding error.
- **One verdict for whether this machine is protected.** `Service.State()`
  returns exactly one of `observing`, `enforcing`, `partial`, `degraded`,
  `unverified` or `unable`, and every screen, endpoint and metric derives from
  it instead of reading the health flag directly. The order is deliberate:
  observe mode first, because it is a setting and not a fault; then whether the
  backend can enforce at all; then whether anyone has looked, and whether they
  looked recently enough. A passing verification stops counting as evidence
  three verify intervals after it was taken.
- **"Why is this blocked?" has an answer.** A block recorded a free-text
  reason and nothing else — no actor, no evidence, no link to the alert that
  caused it — and past the audit log's fifty-row window the question had no
  answer at all. Blocks now carry provenance, and the audit log takes a filter
  on actor, action, target and time window. Rows written before this release
  have no actor rather than a plausible one: silence, not attribution. Paging
  is keyset rather than offset, because a log still being written shifts under
  an offset and pages then repeat or drop entries, which in an audit log means
  answering "nothing happened" when something did.
- **Skopos records what it does to itself.** A self-heal rebuilds the whole
  ruleset without the operator; it used to leave two log lines and nothing in
  the place they would actually look. That, and a block released because the
  allowlist grew to cover it, now write audit entries.
- **A read-only view of what the kernel actually holds.** `GET
  /api/firewall/kernel` reads the fourteen sets and three chains back, with the
  ranges each set contains. An unknown count is null and never zero, and a dump
  that failed outright answers 503 with no snapshot rather than an empty one —
  "the firewall holds nothing" is the alarming answer this exists to be able to
  give, so it must only ever give it when it is true.
- **`GET /api/config` says which file is in force.** A mistyped mount means
  Skopos never read the configuration, runs on defaults, and looks entirely
  normal while showing settings that are not the operator's. The endpoint
  reports the path tried, whether it was found, and which keys in that file are
  inert, each with the reason. No secret is included.
- **Alerts have a retention bound.** `storage.retention.alerts` defaults to
  365d and is pruned hourly. It was the last table growing without one, on a
  box whose disk is also the household's storage. An incident is deleted with
  the last of its alerts and never before, so the view cannot offer an episode
  whose events are gone. The three new coverage tables age out with the rollup
  each one qualifies, never before it.
- **`logging.file` writes a log file.** It defaulted to true and produced
  nothing, so after an incident there was nothing to read — container stdout
  dies with the container, which is exactly when you want it. JSON lines now go
  to `<cold>/logs/skopos.log`, rotating at `logging.max_size` and keeping
  `logging.max_backups` files, `0750` on the directory and `0640` on the file
  because these lines name household hosts. Unmounted cold storage warns once
  and keeps monitoring rather than refusing to start.
- **`server.trusted_proxies`** names the networks, in CIDR form, whose
  `X-Forwarded-For` header Skopos will believe. It defaults to empty. A
  malformed entry refuses to start rather than being dropped, since a silently
  ignored one leaves an operator believing in protection they do not have.
- **The notification lands on the alert it woke you for.** ntfy sends you to
  `/alerts/<id>`; the route existed and never read its parameter, so a tap at
  three in the morning arrived at an unfiltered list of two hundred rows.
  There are now `/alerts/:id` and `/incidents/:id` pages carrying severity,
  source with its device name, detectors, first and last seen, reputation, the
  event list and the three actions. An id outside the current page says so and
  links out rather than quietly showing the list.
- **The URL carries the view.** Time range, filters and search now live in the
  address bar, so reloading keeps the context, a view can be sent to someone
  else, and the back button undoes the filter instead of leaving the page.
  Absolute timestamps deliberately never enter the URL — the window is resolved
  at fetch time.
- **A status strip on every page** states capture, enforcement and outstanding
  alerts with four states each. Unknown is grey and names the endpoint it could
  not reach, rather than being drawn as either good or bad.
- **New metrics.** `skopos_capture_keep_rate`, `skopos_capture_sources_up`,
  `skopos_capture_sources_total`, `skopos_capture_up`,
  `skopos_capture_last_packet_timestamp_seconds`,
  `skopos_firewall_kernel_verified`, `skopos_firewall_kernel_sets_checked`,
  `skopos_firewall_kernel_checked_timestamp_seconds` and
  `skopos_firewall_kernel_failing_since_seconds`. The two timestamps are absent
  rather than zero when the kernel has never been read: a zero timestamp is
  1970, and an alert on "checked more than ten minutes ago" would then fire
  forever on a monitor-only install.

### Changed

- **Ten navigation entries became eight.** Overview is now Now; Live is the
  leftmost position on Traffic's time control rather than a separate page, with
  the same five filters either side of it; Domains is a lens on Traffic. Nothing
  was deleted — two pages stopped presenting themselves as destinations — and
  the search palette still matches "overview", "live" and "domains" to the pages
  they became. The eight are grouped as Watch, Protect and Skopos. On a phone
  four of them are tabs and the rest sit behind More.
- **The theme defaults to `system` instead of always-dark.** Anyone who never
  touched the toggle will see the dashboard follow their operating system on
  first load after upgrading. An explicit choice is unaffected. Both palettes
  are separately tuned and held to the same contrast thresholds.
- **The primary button's label is readable.** White on the accent measured
  2.30:1 in dark, which was the default theme, so every confirming action in
  the product — Block, Save, Apply — carried a label close to unreadable, and
  had since the palette was written. It is 7.55:1 in dark and 6.38:1 in light
  now, from a single token that is the only source of text on accent.
- **Endpoint shapes.** `/api/blocks` carries the full enforcement verdict where
  its `kernel` field used to carry the narrower kernel-health object; that
  object's `contents_checked` is now `sets_checked`. `/api/overview` and
  `/api/health` gain an `enforcement` object beside the existing `enforcing`
  boolean. `/api/overview` and `/api/flows` return dense series with a `state`
  discriminator, a `coverage` summary and `bucket_seconds`. Live throughput
  fields are omitted when there is no reading rather than sent as zero. Old
  fields keep their old meanings: `enforcing` is still the configuration's
  intention and `skopos_firewall_enforcing` still scrapes as it always has,
  because silently changing what an existing signal means would leave a
  dashboard telling a different story with nobody having touched it.
- **Prometheus throughput gauges are absent when the capture is not running**,
  so a scrape renders a gap rather than a floor of zero that looks exactly like
  a quiet network.
- **A response omits what it could not fetch.** Overview, device detail and the
  traffic series list the keys they failed to answer in an `unavailable` array
  instead of filling in a zero. "Unacked alerts 0", in green, was what an
  unreachable database used to look like.
- **Detector state is bounded and the bounds report themselves.** The country
  throttle no longer sweeps its whole memo on every SYN, the port-scan detector
  maintains its distinct-port and distinct-target counts as attempts enter and
  leave rather than rebuilding two maps over 4096 attempts, and the policy
  cooldown and behavioural baseline are capped and aged like their neighbours.
  Measured here: the country-block distinct-source path went from 366,088 to
  872 ns/op and the port-scan SYN-flood path from 170,664 to 428 ns/op. No
  threshold or semantic changed below any cap. Above one, entries shed to stay
  inside the bound are counted per detector rather than discarded quietly —
  silent discarding is how the baseline detector went deaf in the first place —
  though those counters are not yet exposed on `/metrics`.
- **`capture.rdns` and `capture.flow_idle_timeout` are documented as inert.**
  Both are still accepted so existing files keep loading. No address is looked
  up in reverse today, and every open flow is flushed on the `flow_flush` tick
  whether it has been silent or not. `storage.archive_at` is inert in the same
  way, and its comment no longer describes an export that does not happen.
- **The 0.3.3 notes overstated the kernel self-check.** They said it reads the
  contents of all fourteen sets. It confirms every set exists and that no set
  Skopos holds rules for sits empty — an emptiness invariant, not a comparison.
  A set filled with entirely the wrong addresses is not empty and passes. That
  is the right check: coalescing merges ranges and interval sets store two
  elements per range, so exact comparison would flag healthy kernels, and a
  check that cries wolf gets ignored. The implementation was never in question.

### Fixed

- **A stranger could choose which addresses the firewall proposed to block.**
  Only the first fragment of an IPv4 datagram carries the transport header;
  every later one is payload. The parser never looked at the fragment offset,
  so it read payload bytes as ports and TCP flags and manufactured apparent SYNs
  from whatever was being transferred, under whatever source address the outer
  header claimed. Those reached the rate, port-scan and country detectors, and a
  detector finding carries a block suggestion — so a resolver, an update server
  or anything else could be picked out for blocking by someone who could send
  fragments to this host. Later fragments now keep their addresses and protocol
  and report no ports and no flags, the shape ICMP already had. Their bytes stay
  counted, because they are real. First fragments are untouched.
- **`X-Forwarded-For` was believed from any source.** The header was read
  before anything looked at who sent it, and its only caller is the login rate
  limiter, which counts failed attempts per client — so a fresh value on each
  request made every attempt a first offence and the count never reached the
  threshold. It is now read only for connections from a network named in
  `server.trusted_proxies`. Configuration parsing moved ahead of opening the
  database, so a bad value costs nothing to find.
- **The privacy switches switched nothing.** `capture.dns` and `capture.sni`
  were documented, defaulted to on and read by no one: the parser lifted DNS
  names and TLS server names out of every packet regardless, so someone who
  set `dns: false` to stop recording which sites their household visits was
  recording them anyway. The gates now sit in the parser rather than downstream
  of it, so with a switch off the names are never read out of the packet and
  there is no filtered copy to leak later. Turning off `dns` also gives up mDNS
  device hostnames; turning off `sni` also ends the JA4 client fingerprint,
  which comes out of the same handshake. Removing the switches was the other
  option and it was the wrong one.
- **Charts draw the gap instead of a line across it**, and the tooltip
  distinguishes "capture down" from "not recorded", because those are different
  admissions. The densifier is shared rather than reimplemented per view, since
  a second implementation is a second chance to reintroduce this.
- **Three subsystems read a firewall flag computed once at startup.** Switch
  the firewall to observe at noon and until the process restarted the live view
  went on marking flows "dropped" that nothing was dropping, country coverage
  went on reporting addresses as blocked that the kernel had stopped holding,
  and the policy engine went on suppressing alerts about those sources on the
  grounds that the firewall was handling them. The last is the worst: the other
  two show something wrong, that one shows nothing at all, silently, for exactly
  the sources someone had decided were worth watching. All three now ask the
  kernel verdict, which is conservative by construction — anything short of a
  fresh confirmed pass reads as false.
- **A recorded verification never expired.** If the verify goroutine died,
  panicked or was never started, the pass stayed recorded for the life of the
  process and every screen went on reporting protection from a reading that
  could be days old. Three verify intervals past the last reading the verdict
  demotes to unverified.
- **The dashboard could show old numbers as current.** The API client had no
  timeout, and `fetch` imposes none, so a NAS that accepts the connection and
  then stops answering left the promise pending forever — nothing rejected, so
  nothing marked the data stale, and the page sat there showing figures from
  before the trouble. Requests now abort at twenty seconds and a timeout is
  raised as status 0, "never reached the server", because an unanswered request
  may still have been applied and the caller has to be able to branch on that.
  Staleness is derived from the clock as well as from errors — three missed
  polls, never under ten seconds — because an error is visible and silence is
  not. Polling became a chained timeout with one request in flight: an interval
  keeps firing while a request is still running, so a NAS slower than the poll
  period accumulates overlapping requests against the single database
  connection they are all queued behind, and the load rises because the load is
  high.
- **Four actions failed silently.** Unblock, acknowledging an alert,
  acknowledging an incident and unmuting were awaited without a catch, so a
  rejection did nothing visible: the click appeared to work, the list
  refreshed, and the operator walked away with a belief that may have been
  wrong. Unblock is the dangerous one — the server answers that the firewall
  rejected the change and the block is still in place, and nobody saw it. The
  toast host had been built and never mounted; it is mounted above the routes
  now, so an outcome survives the navigation that produced it. Server errors
  are translated into what happened and, more importantly, what is true now:
  nothing was changed, or the block is still in place, or the entry was rolled
  back. The kernel's own wording — "file exists" — no longer reaches anyone. A
  5xx declines to guess, and says to reload and look.
- **The Cloudflare tiles reported "Threats 0" in green after a failed fetch.**
  They take null now and say Cloudflare did not answer, and a cache hit rate
  over zero requests is undefined rather than 0%.
- **Device detail dropped five query errors on the floor**, producing a page of
  confident empties — no destinations, no ports, a flat chart — whenever the
  database could not answer. It names what it could not fetch, and the volume
  tile says how many buckets were never captured instead of folding them into
  the total as zeroes.
- **Traffic froze its time window at page open** and polled that same pair
  forever, so "last hour" meant a day ago after a day.
- **A 404 rendered the dashboard**, which made a broken link look like a
  working one.
- **The System audit log hid roughly half of every row on a phone.** At 390px
  the table put the Detail column — the one that says what happened — past the
  right edge, with no scrollbar and no other sign there was more. It renders as
  cards now. An audit log that hides half of each entry is worse than none,
  because it looks complete.
- **A caller-supplied `limit` on the alerts and audit endpoints is clamped at
  1000**, matching incidents. One request could previously materialise the
  table and stall the single database connection every other query shares.

### Upgrading

- **Three migrations run on the first start after upgrading: 0010 (capture
  coverage), 0011 (rollup direction) and 0012 (block provenance).** All are
  additive and none rewrites a row: 0010 creates three tables, 0011 and 0012
  add nullable columns with no default, and 0012 adds two audit indexes.
- **Rolling the image back is refused, not attempted.** A database written by a
  newer build makes an older one exit with the two version numbers rather than
  starting against a schema it does not know. Take a backup before upgrading if
  you want a way back.
- **History from before the upgrade is marked as not recorded, and that is
  deliberate.** Buckets predating migration 0010 have no coverage record, so
  they render as `unverified`: the byte counts are shown, because a rollup row
  exists only where flows were flushed into it, but nothing says whether
  sampling was active or an interface was down. Buckets predating 0011 have no
  upload/download split and show none — `DEFAULT 0` would have asserted that
  every byte of the last three months was inbound, a fabricated measurement in
  the right units across tables kept for 90 and 730 days. Both states shrink to
  zero as that history ages out of the rollups. Charts say so in words, because
  a missing band cannot say it for itself.
- **The theme default changes from dark to system.** If you never touched the
  toggle, the dashboard will follow your operating system after this upgrade.
  Set it explicitly in Settings to pin it.
- **`storage.retention.alerts` is new and defaults to 365d.** If you have alert
  history older than a year it will be pruned on the next hourly pass, together
  with the incidents whose last alert falls before the cutoff. Set it to `0` to
  keep everything.
- **`logging.file` starts writing.** It defaulted to true and did nothing, so
  after upgrading a box that never changed it, JSON logs will begin
  accumulating under `<cold>/logs` up to `max_size` × (`max_backups` + 1). Set
  `logging.file: false` if you do not want them.
- **`capture.dns: false` and `capture.sni: false` start taking effect.** If you
  set either expecting it to work, it now does: DNS-derived and SNI-derived
  names stop being recorded from that point, mDNS device hostnames go with
  `dns`, and JA4 fingerprints go with `sni`. Existing stored names are not
  removed.
- **API consumers:** `/api/blocks`'s `kernel` field changed shape and its
  `contents_checked` key is now `sets_checked`. Throughput series are dense and
  their `bytes`, `packets` and `flows` are null on `down` and `nodata` buckets,
  so a client that assumed numbers are always present needs to handle null.
  Live throughput fields are omitted rather than zero when there is no reading.
  Prometheus throughput gauges are absent from the scrape while the capture is
  not running. `enforcing` and `skopos_firewall_enforcing` are unchanged.

## [0.3.3] - 2026-08-14

An eleven-person review round, and the one thing worth saying up front: the
operator reported an error message, and the error message was the honest part.
Blocking an address from an alert showed "file exists" and created the entry
anyway. The entry was the lie.

The kernel refuses overlapping ranges inside a set, and Skopos pushes the whole
block list in one atomic batch. So a single overlapping pair — an address
blocked from an alert, plus the network around it blocked from the same dialog
a day later — failed that batch, and because the batch is atomic and the list
is rebuilt from scratch every time, **every subsequent block, unblock and
expiry silently stopped reaching the kernel**, for every address. After a
restart it was worse: the firewall enforced nothing at all while the dashboard
listed every block as active.

The same defect sat in the never-block list, and there it needed no mistake at
all. The allowlist gets the default gateway appended to it, so allowlisting
your own LAN — exactly what the example configuration suggests — produced an
overlapping pair on a clean install, and startup aborted before it programmed a
single rule. A box configured that way had been enforcing nothing since its
first boot, and saying otherwise on every screen.

Behind that sat the reason none of it was visible: enforcement was reported
from intent. The configuration said enforce, netlink opened, so the dashboard
said enforcing. Nothing ever asked the kernel.

### Added

- **The firewall checks itself, against the kernel.** Every two minutes Skopos
  reads back what the kernel actually holds — the table, all three chains,
  their exact rule counts, and all fourteen sets, none of which may sit empty
  while Skopos holds rules for it — and rebuilds from the stored state when any
  of it is missing. It detects a wiped ruleset, a
  deleted or flushed chain, a single deleted rule, and an emptied set, and it
  repairs all of them without waiting for anyone to notice. What it found and
  when is reported as it happened, so a view can say "unconfirmed since 09:14"
  instead of painting rows green on the strength of a configuration file.
  This is the thing that would have caught the 0.2.1 defect, this round's, and
  the next one.

### Fixed

- **Overlapping blocks no longer wedge the firewall.** Ranges are cut into
  non-overlapping pieces before the kernel sees them. Merging alone would not
  do: a permanent /24 absorbing a one-hour /32 really is one permanent range,
  but a one-hour /24 containing a permanent /32 is not — collapsing that to the
  longer expiry would hold 255 uninvolved addresses blocked forever. Each piece
  takes the right deadline, and pieces rejoin only when their deadlines agree.
  Existing installations repair themselves on the next pass.
- **The never-block list loads even when it overlaps itself**, so an allowlist
  containing its own gateway no longer stops the firewall coming up.
- **A block that the kernel refuses leaves nothing behind.** The stored row is
  rolled back and the attempt goes to the audit log, where a record of
  something that did not happen belongs. Unblocking works the same way in
  reverse: if the kernel will not lift it, the row stays and you are told the
  block is still in place. Neither door shows you the kernel's own wording any
  more.
- **Enforcement status comes from the kernel.** It used to check the
  configuration and whether netlink opened — never whether the rules existed —
  so a failed startup left the dashboard, the health endpoint and the metrics
  all green over an empty kernel.
- **Blocking a whole address family is refused.** On IPv4 it wedged the
  reconciler; on IPv6 it was accepted, dropped every packet in all three
  chains, and returned success. Ranges that genuinely reach the top of an
  address family — 255.255.255.0/24, 240.0.0.0/4 — work correctly instead of
  being silently discarded.
- **The throughput chart was 60x too high** on every range longer than twelve
  hours, and on every window of the device page. The server picks a coarser
  bucket as the range grows and says which it used; the chart divided by a
  fixed sixty regardless, and labelled the result "average bits per second".
- **History search answered investigations with a false negative.** A subnet
  search applied its row limit before the address filter, so it fetched the
  newest few hundred flows regardless of address, discarded the ones outside
  the range, and reported "Nothing matched" while the matches sat just past the
  cut. It also now says when there are more matches than fit, rather than
  presenting a capped page as the whole answer.
- **One query parameter was a denial of service.** Asking for minute buckets
  across ninety days took forty-five seconds where the same range at the right
  resolution took a third of a millisecond — and every query in Skopos shares
  one database connection, so it stalled traffic recording and every other page
  along with it. The requested resolution is now clamped to what the span
  warrants.
- **The reputation card stopped reading silence as a clean result.** The
  regression caught in 0.3.0 was still there, inside the code written to fix
  it: any well-formed reply, including a rate-limit notice, decoded to "no
  reports" and was cached for a day. blocklist.de reported a confident zero
  from a half-parsed reply, and stayed silent entirely when it could not answer
  at all. And "not on your blocklists" was stated as fact when no blocklist had
  loaded.
- **The device tracker no longer dies on its first write error** — it used to
  end permanently and without a single log line, taking new-device alerts and
  presence tracking with it, and then freezing last-seen timestamps so the
  presence watcher announced that devices had left when they had not. Both it
  and the flow writer now report degradation and recovery through the
  notification channel, once each, rather than into a log file.
- **The detectors no longer go deaf.** Port-scan and rate detection kept
  per-source state that was never reclaimed; past 8192 distinct addresses they
  stopped tracking anything new, permanently. On a box with a forwarded port
  that ceiling arrives in days, and it arrives with the table full of addresses
  last heard from weeks earlier while the one attacking right now is ignored.
  Sources silent for several detection windows are now reclaimed; active ones
  never are, because evicting those is exactly what a flood of spoofed
  addresses would be trying to achieve.
- **The rate detector no longer cuts off your own network.** A backup or an
  rsync opens hundreds of connections in seconds — ordinary on a LAN — and the
  threshold tuned for a flood from the internet auto-blocked the machine doing
  it, mid-transfer. LAN sources are held to a proportionally higher bar and are
  never proposed for an automatic block.
- **Acknowledging an alert no longer undoes itself.** A poll already in flight
  could land after the acknowledgement and put the row back, with no error and
  nothing to click — on the one screen where "did that register" is the whole
  question.
- **The live tiles admit when they have no reading.** A green "Full · every
  packet" and 0 bit/s before the first measurement made a dead capture look
  like a calm network. The settings card read enforcement from the
  configuration string, so it could show a green pill while the firewall view
  showed the degraded banner — the app contradicting itself about one fact.
  An unreadable country list no longer renders as "No countries blocked", and
  device names now resolve for IPv6 as well as IPv4.
- **The documentation stopped promising a spool buffer** that does not exist.
  The correction in 0.3.2 reached the README and the configuration reference
  and missed seven other places, including the page strangers read first.

## [0.3.2] - 2026-08-14

Seven reviewers went through the codebase together. What they found was
mostly the same shape: controls that reached less far than they claimed, and
failures that stayed quiet. Preventive country blocking had been switching
itself off since 0.2.1. Turning on two-factor authentication locked you out
of your own dashboard. A full disk ended traffic recording for good while
everything still looked alive. The never-block allowlist could be walked past
four different ways. None of it announced itself, which is exactly why it
lasted.

### Added

- **Block from the alert** — every alert and every incident has a Block
  button. It opens with the address filled in and asks the three things that
  matter: how far to reach (that address, or its /24 or /64), how long (1h,
  24h, 7d, or blank for permanent), and why. The note is not decoration — in
  a month "why is this blocked?" is the only question you will have, and it
  follows the block into the Firewall view and the audit log. Before you
  commit, the dialog says whether enforcement is even on, whether the address
  is already blocked and until when, and whether the block would cover
  something protected.

### Fixed

- **Preventive country blocking was being switched off by ordinary blocks.**
  The reconciler that owns the four per-IP block sets was emptying every set
  in the table and refilling only its own, so each block or unblock silently
  cleared the country sets, the LAN ranges the per-device rules compare
  against, and the never-block set. On a box with an active detector that
  meant country blocking was down most of the time while the dashboard went
  on reporting the prefix count it had last loaded, and "LAN only" quietly
  became a full quarantine, since with no LAN ranges loaded every peer counts
  as outside. Present since preventive country blocking shipped in 0.2.1. An
  integration test against a real kernel now asserts that a block leaves
  every other set exactly as it was.
- **Turning on two-factor authentication locked you out of the dashboard.**
  The server answers "password correct, now the one-time code" as a 401 with
  a flag in the body, and the API client threw that body away unread on every
  401 — so the login form never learned to ask for the code and reported
  invalid credentials for a password that was right. The only way back in was
  deleting rows from the database.
- **A detector firing stalled packet capture.** Handling a finding did the
  database write, the ntfy request and the kernel call on the goroutine
  reading frames off the wire, so one alert could stop capture on that
  interface for as long as the notification took — up to fifteen seconds per
  channel, during an attack, which is when the findings come. That work
  happens on its own now. If it ever falls behind, findings are dropped and
  counted rather than allowed to block capture, and the count is a metric.
- **The rate detector could not keep up with its own default settings.** It
  kept one timestamp per packet per source and shifted the whole backlog
  forward on every packet — at the shipped 8000 packets per second that is
  more work per millisecond than a millisecond contains, and the memory grew
  without bound. It counts into a fixed ring of buckets now: same answer,
  constant memory, measured at 34 nanoseconds per packet. The per-source maps
  in the rate, port-scan and blocklist detectors are bounded too.
- **A LAN device with a real IPv6 address counted as the internet.** The
  private ranges cover RFC1918, ULA and link-local but not the globally
  routable addresses an ISP-delegated prefix hands every device — which is
  what most dual-stack homes actually run. That picked the wrong end of the
  flow for blocklist matching, hid inbound attacks on a device's own address
  from the country detector, judged ordinary local traffic against the strict
  external thresholds, and left the behavioural baseline with nothing to
  learn from. The on-link global prefixes are now found at startup and
  treated as local.
- **A panic in one subsystem no longer takes the rest down with it.** Every
  loop is contained and reports what stopped. The flow aggregator was the
  sharpest case: any write failure ended it permanently and in silence while
  the detectors carried on alerting, so Skopos looked alive while it had
  stopped recording anything.
- **Cold storage never held flow archives.** The documentation described
  Parquet archives, a spool buffer for when cold storage is unreachable, and
  a nightly export — none of which was ever built. Raw flows past their
  retention are deleted, and the daily backup is the durable copy. The
  documentation says that now, and the two settings that fed the missing
  feature say plainly that they do nothing.
- **Rolling back to an older image no longer starts against a newer
  database.** It refuses, naming both schema versions, rather than running on
  a schema it does not know.
- **The database was carrying a duplicate of itself.** Three rollup indexes
  repeated their own tables' primary keys — measured at roughly half the file
  on a year of traffic. Dropped, which gives that space back to the retention
  cap.
- **A full disk no longer ends flow recording permanently.** One failed write
  used to end the loop that writes history for good — nothing was recorded
  again until someone restarted the container, even after the space came
  back. It retries on the next tick and reports the failure instead.
- **The hot-storage cap says when it cannot hold.** It only ever deletes raw
  flows, never the rollups, so once the rollups alone exceed the limit the cap
  silently stops being a cap and every run empties the raw flows — collapsing
  the documented seven days of history to about an hour, permanently and with
  no sign of it. That case now reports itself and pushes a notification.
- **Incidents were never pruned.** The pruner existed and nothing called it,
  so the table only ever grew. It follows the same retention window as the
  names it sits beside.
- **A stalled connection can no longer take the dashboard down.** The HTTP
  server had no header or idle timeout, so a connection that opened and then
  said nothing held a goroutine indefinitely — enough, on a port forwarded to
  the internet, to exhaust the server without a single request completing.
- **CSV exports cannot smuggle a spreadsheet formula.** Device labels and the
  hostnames learned from mDNS are not necessarily chosen by a human, and a
  value beginning with =, +, - or @ runs as a formula when the file is opened
  in Excel or Sheets. Those cells are quoted as text now.
- **The never-block allowlist now holds on every path.** Blocks placed by
  hand went straight to the kernel without consulting it, and so did
  per-device policies — the worse of the two, because device rules sit ahead
  of the conntrack exemption and cut connections already in progress, so
  confining the router would have taken down the network the dashboard is
  reached over. Both refuse now and name the allowlist entry they hit, and
  the device path is filtered at the firewall service as well, so a policy
  stored before this guard cannot reach the kernel either.

## [0.3.1] - 2026-08-13

### Fixed

- **The device list inventories devices again.** It used to file the
  link-layer address of any frame whose IP side looked local, so a subnet
  broadcast became a neighbour called `192.168.1.255 (ff:ff:ff:ff:ff:ff)` and
  every mDNS or SSDP group got an entry of its own. Group addresses belong to
  no machine and are now skipped, and the upgrade removes the entries they
  already left behind — except any you named, restricted or watched, which are
  kept whatever they look like.
- **One address no longer grows a dozen entries.** Traffic that presents a
  fresh hardware address per sighting — a tunnel, a relay re-framing other
  hosts' packets, a NIC randomising its MAC — used to add an inventory row and
  a "new device" alert every time. An address that several MACs have claimed
  has shown that its MAC means nothing, so it stops creating entries, and the
  list offers to clear out the ones already there.
- **Dual-stack devices keep both addresses.** IPv4 and IPv6 have separate
  columns, so a device that last spoke over IPv6 no longer shows
  `fe80::8f5:45d3:3bc2:b3ea` where its LAN address used to be. A link-local
  address never displaces a routable one, and a per-device policy now covers
  both families — a quarantine with a working IPv6 path was not a quarantine.
- **Capture handles links that are not Ethernet.** On a VPN tunnel, a PPP link
  or a 6in4 interface there is no Ethernet header, and reading the first
  fourteen bytes as one invented hardware addresses that never existed. Those
  interfaces are now parsed as what they carry: bare IP packets, with no MACs.
- **"Abuse 0%" no longer sits next to a critical alert.** An address no free
  source happened to have data on was rendered as a confident green zero,
  which reads as "this one is fine" — including for addresses Skopos had just
  matched against a blocklist itself. Nothing found now says so: unknown, not
  cleared, never green.
- **The country is where the address is.** It came from the registry, which
  records where the address holder is incorporated — so a Dutch data centre
  whose operator is registered in Andorra was reported as Andorra. The local
  GeoIP database answers first now, and a registry country is labelled
  "Registered in" so the difference is visible rather than misleading.

### Added

- **Devices you can find and tidy.** The list has a search box, shows both of
  a device's addresses, marks randomised MACs as what they are, and can forget
  an entry — singly, or all the noise at once after showing you exactly which
  entries it means. Forgetting is safe: discovery is passive, so anything
  still on the network is back within seconds.
- **Hostnames without asking anyone.** Devices that announce themselves over
  mDNS are inventoried under that name, so the list reads "printer.local"
  instead of a bare MAC address.
- **More sources behind "who is this?"** — the blocklists Skopos already
  downloads (answered from memory, no request), blocklist.de's fail2ban
  reports alongside DShield's sensor data, and the local GeoIP database. Each
  source's answer is shown separately, so a number can be checked instead of
  trusted, and the strongest reading wins rather than being averaged away by
  sources that have never heard of the address. Still no account and no API
  key anywhere. Where the free sources are thin, the card links straight to
  the AbuseIPDB, Shodan and VirusTotal pages for the address — plain links,
  nothing is sent until you click one.

## [0.3.0] - 2026-08-13

Skopos learns your network's language. Traffic arrives with names instead of
addresses, the dashboard can be steered without touching a file, and every
control says exactly how far it reaches.

### Added

- **Names instead of addresses** — Skopos now reads the DNS and mDNS answers
  and TLS server names that pass the wire, so flows, top destinations and
  alerts show `youtube.com` where they used to show `142.250.185.78`. Learned
  passively from traffic Skopos already sees: nothing is queried, nothing is
  sent anywhere, and names survive restarts.
- **Domains view** — which domains the network contacted, by volume, for the
  last hour/day/week, and the same list per device on its detail page.
- **TLS client fingerprints (JA4)** — each device's TLS handshakes are
  fingerprinted, identifying client software independently of address or
  port. Shown per device; the same browser keeps the same fingerprint even
  when it shuffles cipher order.
- **Prometheus metrics** — `/metrics` now actually exists (the config knob
  had nothing behind it): throughput, enforcement state, active blocks,
  unacked alerts, per-block drop counters and per-country prefix counts.
- **Behavioural baseline** — Skopos learns each device's usual hourly volume
  and reports departures from it: the printer that suddenly uploads a
  gigabyte, the camera that starts talking at 3am. It needs a few hours of
  history before it judges anything, has an absolute floor so a quiet device
  cannot alert over a kilobyte, and never suggests a block — unusual is not
  malicious.
- **Search the history** — the Traffic view can query the raw flow records by
  address (or CIDR), port, protocol, direction and domain over a window, for
  the question the aggregates cannot answer: what actually happened at 3am.
- **Notification buttons** — ntfy pushes carry "Block 24h" and "Mute"
  buttons. Each is a signed, single-purpose, expiring link: a leaked
  notification grants one temporary block of one address, never API access.
  They appear once `server.external_url` is set.
- **Mirror-port mode** — declare a switch SPAN/tap interface under
  `capture.mirror.interfaces` and Skopos sees the whole segment instead of
  only this machine's traffic. The System view says which of the two you are
  getting, since visibility and enforcement have different reach.
- **Incidents** — the Alerts view groups events by source and episode: one
  attacker with forty scan attempts is one row saying "40 events", expandable
  to the individual alerts, acknowledgeable in one click. Two hours of quiet
  starts a new episode, so today's visit is not merged with last week's. The
  flat list stays one click away.
- **Mute rules** — silence an alert pattern by detector, source prefix, port
  or any combination, permanently or with a TTL. Muting stops the alert and
  the notification and nothing else: blocking still applies exactly as
  configured, because a noise control that quietly disarmed protection would
  be a trap.
- **Per-device policy** — confine a device from its detail page: "LAN only"
  drops its traffic to and from the internet, "Quarantine" drops everything
  including local traffic. Implemented as kernel rules keyed on the device's
  address, ahead of the conntrack exemption so an established connection is
  cut too, and re-derived every 30 seconds so a DHCP lease change follows the
  device. The UI states plainly that this reaches only traffic passing the
  machine running Skopos.
- **Settings you can actually change** — enforcement, automatic block
  lifetime, alert cooldown, the never-block allowlist and both threshold
  detectors are now editable in the dashboard and apply immediately. No
  file editing, no restart: arming the firewall is one click. The YAML
  stays the baseline, the UI marks what you changed away from it, and
  "Reset to config.yaml" drops every override. Invalid values are refused
  as a whole, so a bad patch can never leave the firewall half-armed, and
  every change lands in the audit log.
- **Release check** — a daily look at the public releases page, a banner in
  the System view and one notification per new version, so a stale image
  cannot go unnoticed. Off with `updates.check: false`.

### Changed

- **IP reputation now works without any account.** Attack history comes from
  DShield (SANS Internet Storm Center) alongside RDAP ownership — both open,
  keyless sources — so the "who is this?" lookup is fully populated on a
  fresh install instead of asking the operator to register for an API key
  and paste it into Settings. The API-key handling and its Settings card are
  gone with it.

## [0.2.2] - 2026-08-13

Country blocking learns the difference between an attack and an answer.

### Fixed

- Reactive country blocking no longer blocks the far end of connections your
  own devices opened. It used to fire on the reply packets that the conntrack
  exemption deliberately lets through — killing exactly the traffic the
  exemption protects (Skopos' own RDAP lookup against a Brazilian registry
  being the first casualty). It now reacts only to inbound connection
  attempts (TCP SYN).
- Sources already dropped by the preventive country sets no longer generate
  "Traffic from blocked country" alerts and redundant per-IP blocks; the
  kernel handles them, the live view badges them.
- The live view's `blocked` badge is honest now: it only appears when
  enforcement is actually active (observe mode drops nothing), and flows
  covered by country blocking are badged too — previously only per-IP blocks
  were.

## [0.2.1] - 2026-08-13

Blocking you can believe: the firewall now proves it is working, whole
countries are dropped preventively, and observe mode stops pretending.

### Added

- **World map** — the Traffic view renders the country statistics as a
  choropleth (outbound/inbound toggle), volume-scaled in the accent hue.
- **Preventive country blocking** — listed countries' networks are enumerated
  from the GeoIP database and loaded into dedicated kernel sets, so their
  traffic is dropped on arrival instead of only after a source has already
  appeared once. Inbound-only behind a conntrack exemption: connections your
  own devices open toward those countries keep working. The country chips
  show how many networks are loaded; the reactive block-on-sight detector
  stays as backstop while the database is still downloading.
- **Proof the firewall works** — every block now counts the packets seen
  from/to its prefix ("Dropped" in enforce mode, "Would drop" in observe
  mode, with the last-attempt time), and live-view flows touching an active
  block carry a `blocked` badge. The capture tap sits before netfilter, so
  blocked traffic remains visible while the kernel discards it — previously
  that read as "blocking doesn't work".

### Changed

- **Observe mode is now unmistakable.** The Firewall view banners when
  enforcement is off ("nothing is actually blocked") or the backend is
  unavailable, the Overview tile turns amber in observe mode, and alerts for
  sources the kernel already drops are suppressed — their ongoing attempts
  show in the per-block counters instead of re-alerting as if the block had
  failed.

### Fixed

- Blocklist feeds no longer raise alerts for bogon space. Border lists like
  FireHOL Level 1 include multicast, broadcast, CGNAT and RFC1918 ranges by
  design; inside a LAN those matched everyday mDNS/SSDP/DHCP traffic and
  produced critical alerts for addresses like 239.255.255.250. Feed matches
  now only consider routable public unicast addresses.

## [0.2.0] - 2026-08-12

The dashboard grows up: real-time everything, devices you can name and wake,
Cloudflare and GeoIP context for your traffic, and a hand-built phone
experience.

### Added

- **Live view** — every conversation as it completes, streamed over SSE with
  throughput updating once a second; filter by device, IP, port, protocol or
  direction; pause holds incoming flows aside and counts them on the button.
- **Device naming** — rename any device inline; the label survives restarts,
  is never overwritten by discovery, and takes precedence everywhere —
  including in ntfy alerts ("192.168.1.23 (Living-room TV)"), top talkers,
  blocks and the live feed.
- **Device detail page** — per-device throughput over 24h/7d/30d, top
  destinations with DNS/SNI names, ports with well-known-service labels.
- **Presence tracking** — opt-in arrive/leave notifications per device, with
  hysteresis so a phone parking its Wi-Fi radio does not flap.
- **Wake-on-LAN** — a wake button per device (audited).
- **Cloudflare integration** — connect a scoped API token in the UI (sealed
  with AES-GCM at rest, never in YAML), then monitor per-zone requests, cache
  hit rate and edge-blocked threats for your own domains.
- **GeoIP** — destination and source countries in the Traffic view (DB-IP
  Lite, downloaded at runtime, lookups stay local) and reactive country
  blocking: inbound sources from listed countries are blocked on sight once
  enforcement is on.
- **IP reputation** — a "who is this?" lookup on alerts: owner and country
  via RDAP, plus AbuseIPDB score/reports/ISP with an optional API key.
- **Speedtest monitor** — download/upload/latency every six hours against
  Cloudflare's speed endpoints, with history, on-demand runs and a warning
  when the line drops below half its recent median.
- **Weekly report** — a Sunday-evening ntfy digest: volume with trend, top
  devices by name, alerts per detector, new devices, active blocks.
- **Two-factor authentication** — RFC 6238 TOTP for the single-admin login,
  enrolled via QR code and confirmed with a live code.
- **CSV export** — flows (current range), devices and alerts.
- **Mobile experience** — below 768px the dashboard becomes its own app:
  bottom tab bar, custom bottom sheets instead of dropdowns, and card layouts
  for the live feed and device list.
- **Settings view** — appearance, integrations (Cloudflare, AbuseIPDB), 2FA,
  notification test and version info in one place.

### Changed

- Sidebar navigation grouped into Monitor / Protect / Manage.
- Every `main` build now also publishes an immutable `edge-<commit>` image
  tag next to the moving `edge` tag.

## [0.1.0] - 2026-08-12

The first release: a single container that monitors traffic, manages an
nftables firewall and sends ntfy alerts, configured entirely from one YAML
file.

### Added

- **Traffic monitoring** — AF_PACKET capture with a bounds-checked header
  parser (IPv4/IPv6, VLAN, v6 extension headers), a 5-tuple flow aggregator
  with bidirectional pairing and LAN/WAN classification, an adaptive sampler
  that reports every transition, and a LAN device inventory from ARP/NDP.
- **Storage** — SQLite (WAL) on hot storage with 1m/1h/1d rollups, per-
  resolution retention, a hard hot-size cap that drops oldest raw flows first,
  Parquet archival to cold storage with a spool buffer for when cold is
  offline, and daily online backups.
- **Detection** — port-scan (vertical/horizontal, internal/external
  thresholds), connection-rate, blocklist-feed (FireHOL L1, Spamhaus DROP, or
  any URL, with ETag caching) and new-device detectors.
- **Policy** — severity actions, per-source cooldown with aggregation, quiet
  hours, a never-block allowlist with the gateway hard-wired, and the
  `observe`/`enforce` switch.
- **Firewall** — an nftables backend via netlink (dedicated `inet skopos`
  table, interval+timeout sets, input/forward/output chains), a declarative
  reconciler with restore-on-start and TTL expiry, and graceful degradation to
  monitor-only when the backend is unavailable.
- **Notifications** — ntfy (priority mapping, tags, click-through, token/basic
  auth) and a generic JSON webhook, operational system messages, and a test
  send.
- **API & auth** — REST + SSE, Argon2id single-admin login with signed
  sessions and a login backoff, scoped API tokens, an embedded offline OpenAPI
  reference, and an `auth: none` mode for trusted LANs.
- **Dashboard** — a React + TypeScript UI (Overview, Traffic, Devices,
  Firewall, Alerts, System) with light/dark themes, embedded into the binary.
- **Packaging** — a multi-arch (amd64/arm64) distroless image on GHCR and
  Docker Hub, a reference `docker-compose.yml` with an SSD/HDD volume split, a
  demo mode for a zero-privilege trial, and a full configuration reference
  generated from the source.

[Unreleased]: https://github.com/julianhintermann-cmd/skopos/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.4.0
[0.3.3]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.3.3
[0.3.2]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.3.2
[0.3.1]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.3.1
[0.3.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.3.0
[0.2.2]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.2
[0.2.1]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.1
[0.2.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.0
[0.1.0]: https://github.com/julianhintermann-cmd/skopos/commit/57a56c1
