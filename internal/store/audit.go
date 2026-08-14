package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Audit appends an entry to the tamper-evident action log. Every block,
// unblock, login and configuration-affecting action goes through here.
func (s *Store) Audit(ctx context.Context, e model.AuditEntry) error {
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit (time_ms, actor, action, target, detail)
		VALUES (?,?,?,?,?)`,
		toMs(e.Time), e.Actor, e.Action, e.Target, e.Detail)
	return err
}

// Row bounds for a listing, for the reason set out on alertRowCap: the audit
// table has no retention either, and ListAudit reads it newest-first with no
// window, so an unbounded caller-supplied limit reads all of it across the one
// connection everything else is queued behind.
const (
	defaultAuditRows = 200
	auditRowCap      = 1000
)

// AuditFilter narrows a page of the audit log. The zero value is the whole
// log, newest first — what ListAudit has always returned.
type AuditFilter struct {
	// Actor and Action match exactly. Both are values Skopos itself writes, so
	// narrowing means picking one of them, and migration 0012 indexes both.
	Actor  string
	Action string
	// Target matches on a leading prefix, because the same address is written
	// two ways in this table: a block records "203.0.113.5/32" while a login
	// records the bare address. An operator asking why an address is blocked
	// types the address, and an exact match would answer "nothing" — the worst
	// possible reply from an audit log that does hold the entry.
	Target string
	// Since and Until bound the window: Since inclusive, Until exclusive, both
	// optional. Zero means unbounded on that side rather than the epoch.
	Since time.Time
	Until time.Time
	// Limit caps one page (0, or anything above auditRowCap, falls back to
	// defaultAuditRows).
	Limit int
	// Before continues after a previous page. Zero starts at the newest entry.
	Before AuditCursor
}

// AuditCursor is the position a page continues from: the last entry the
// previous page returned.
//
// Paging is by cursor rather than OFFSET on purpose. OFFSET makes SQLite walk
// and discard every skipped row, so page fifty costs fifty pages of work over
// the single connection every other query in the process queues behind — and
// it silently repeats or drops entries when something is written while an
// operator is paging, which in an audit log is not a display glitch but a
// missing record. A cursor is an index seek and describes a fixed point in the
// log, so the page after it is the same page whatever arrives meanwhile.
type AuditCursor struct {
	TimeMs int64
	ID     int64
}

// Zero reports whether the cursor points nowhere — the start of the log, or
// the end of it.
func (c AuditCursor) Zero() bool { return c.TimeMs == 0 && c.ID == 0 }

// String renders the cursor for a client to hand back verbatim. The empty
// string is the zero cursor.
func (c AuditCursor) String() string {
	if c.Zero() {
		return ""
	}
	return strconv.FormatInt(c.TimeMs, 10) + "." + strconv.FormatInt(c.ID, 10)
}

// ParseAuditCursor reads back what String wrote. An unparseable cursor is an
// error and not a silently ignored one: falling back to the newest entries
// would hand someone paging through the log the top of it again, labelled as
// the continuation, and they would read the same entries twice and conclude
// the ones they were looking for do not exist.
func ParseAuditCursor(s string) (AuditCursor, error) {
	if s == "" {
		return AuditCursor{}, nil
	}
	timeStr, idStr, ok := strings.Cut(s, ".")
	if !ok {
		return AuditCursor{}, fmt.Errorf("audit cursor %q must be <time_ms>.<id>", s)
	}
	ms, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return AuditCursor{}, fmt.Errorf("audit cursor %q has a non-numeric time", s)
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return AuditCursor{}, fmt.Errorf("audit cursor %q has a non-numeric id", s)
	}
	return AuditCursor{TimeMs: ms, ID: id}, nil
}

// AuditPage is one page of the log, newest first, and where to continue.
//
// It carries no total. Counting the matches of a target filter means walking
// the whole table, which is the cost this paging exists to avoid, and a total
// that was true when the page was read is stale by the time it is rendered.
// Next being zero is the honest end marker: it is set from a row that was
// actually read, so a page never offers a continuation that returns nothing.
type AuditPage struct {
	Entries []model.AuditEntry
	Next    AuditCursor
}

// ListAudit returns audit entries most recent first, at most auditRowCap of
// them. It is ListAuditPage with no filter and no cursor.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	page, err := s.ListAuditPage(ctx, AuditFilter{Limit: limit})
	return page.Entries, err
}

// ListAuditPage returns one filtered page of the audit log, newest first.
func (s *Store) ListAuditPage(ctx context.Context, f AuditFilter) (AuditPage, error) {
	limit := f.Limit
	if limit <= 0 || limit > auditRowCap {
		limit = defaultAuditRows
	}

	var where []string
	var args []any
	if f.Actor != "" {
		where = append(where, `actor = ?`)
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		where = append(where, `action = ?`)
		args = append(args, f.Action)
	}
	if f.Target != "" {
		where = append(where, `target LIKE ? ESCAPE '\'`)
		args = append(args, likePrefix(f.Target))
	}
	if !f.Since.IsZero() {
		where = append(where, `time_ms >= ?`)
		args = append(args, toMs(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, `time_ms < ?`)
		args = append(args, toMs(f.Until))
	}
	if !f.Before.Zero() {
		// The id breaks the tie, and it has to: entries written in the same
		// millisecond are ordinary here — a self-heal reapplies a ruleset and
		// audits it in one pass — and a cursor on time alone would either skip
		// its neighbours or return the same one forever.
		where = append(where, `(time_ms < ? OR (time_ms = ? AND id < ?))`)
		args = append(args, f.Before.TimeMs, f.Before.TimeMs, f.Before.ID)
	}

	q := `SELECT id, time_ms, actor, action, target, detail FROM audit`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY time_ms DESC, id DESC LIMIT ?`
	// One row past the page, read and discarded, is what makes the end of the
	// log distinguishable from a page that happens to be exactly full.
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return AuditPage{}, err
	}
	defer func() { _ = rows.Close() }()

	var page AuditPage
	var lastMs, lastID int64
	for rows.Next() {
		var e model.AuditEntry
		var ms int64
		if err := rows.Scan(&e.ID, &ms, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return AuditPage{}, err
		}
		if len(page.Entries) == limit {
			// The extra row: there is more, and it continues after the last
			// entry this page actually returned.
			page.Next = AuditCursor{TimeMs: lastMs, ID: lastID}
			break
		}
		e.Time = fromMs(ms)
		page.Entries = append(page.Entries, e)
		lastMs, lastID = ms, e.ID
	}
	return page, rows.Err()
}

// likePrefix renders s as a LIKE pattern matching anything that starts with
// it. %, _ and the escape itself are escaped: without that, a search for
// "10.0.0.1_" would quietly match "10.0.0.10" too, and an audit filter that
// returns entries nobody asked about is as misleading as one that hides them.
func likePrefix(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + `%`
}
