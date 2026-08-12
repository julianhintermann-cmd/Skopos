package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// Weekly report schedule: Sunday evening, when the week is actually over.
const (
	reportWeekday = time.Sunday
	reportHour    = 18
)

// spawnWeeklyReport delivers a traffic digest once a week through the system
// notification channel (so notify.system.enabled is the off switch).
func (a *App) spawnWeeklyReport(ctx context.Context, spawn func(string, func()), st *store.Store, disp *notify.Dispatcher) {
	spawn("weekly-report", func() {
		for {
			next := nextWeekly(a.clock(), reportWeekday, reportHour)
			timer := time.NewTimer(next.Sub(a.clock()))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				title, body, err := a.buildWeeklyReport(ctx, st)
				if err != nil {
					a.log.Warn("weekly report", "err", err)
					continue
				}
				disp.System(ctx, model.SeverityInfo, title, body)
			}
		}
	})
}

// nextWeekly returns the next occurrence of the given weekday at the given
// local hour, strictly after now.
func nextWeekly(now time.Time, day time.Weekday, hour int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	for next.Weekday() != day || !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// buildWeeklyReport assembles the digest text for the trailing 7 days.
func (a *App) buildWeeklyReport(ctx context.Context, st *store.Store) (title, body string, err error) {
	now := a.clock()
	weekAgo := now.Add(-7 * 24 * time.Hour)
	prevWeek := now.Add(-14 * 24 * time.Hour)

	thisWeek, err := st.SumBytes(ctx, weekAgo, now)
	if err != nil {
		return "", "", err
	}
	lastWeek, _ := st.SumBytes(ctx, prevWeek, weekAgo)

	var b strings.Builder
	fmt.Fprintf(&b, "Traffic: %s%s\n", formatBytes(thisWeek), trendVsLastWeek(thisWeek, lastWeek))

	if talkers, err := st.TopTalkers(ctx, weekAgo, now, store.Res1h, 3); err == nil && len(talkers) > 0 {
		names := make([]string, 0, len(talkers))
		for _, t := range talkers {
			label := t.Address
			if name, err := st.DeviceNameByIP(ctx, t.Address); err == nil && name != "" {
				label = name
			}
			names = append(names, fmt.Sprintf("%s (%s)", label, formatBytes(t.Bytes)))
		}
		fmt.Fprintf(&b, "Top devices: %s\n", strings.Join(names, ", "))
	}

	if counts, err := st.AlertCountsSince(ctx, weekAgo); err == nil && len(counts) > 0 {
		total := 0
		parts := make([]string, 0, len(counts))
		for d, n := range counts {
			total += n
			parts = append(parts, fmt.Sprintf("%s %d", d, n))
		}
		sort.Strings(parts)
		fmt.Fprintf(&b, "Alerts: %d (%s)\n", total, strings.Join(parts, ", "))
	} else {
		b.WriteString("Alerts: none — a quiet week\n")
	}

	if n, err := st.CountDevicesSince(ctx, weekAgo); err == nil && n > 0 {
		fmt.Fprintf(&b, "New devices: %d\n", n)
	}
	if blocks, err := st.ActiveBlocks(ctx); err == nil {
		fmt.Fprintf(&b, "Active blocks: %d\n", len(blocks))
	}

	return "Skopos weekly report", strings.TrimSpace(b.String()), nil
}

func trendVsLastWeek(this, last int64) string {
	if last <= 0 {
		return ""
	}
	pct := float64(this-last) / float64(last) * 100
	switch {
	case pct >= 1:
		return fmt.Sprintf(" (up %.0f%% vs last week)", pct)
	case pct <= -1:
		return fmt.Sprintf(" (down %.0f%% vs last week)", -pct)
	default:
		return " (flat vs last week)"
	}
}

// formatBytes renders a byte count in binary units, matching the dashboard.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
