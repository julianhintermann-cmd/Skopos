package app

import (
	"context"
	"fmt"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

const (
	// presenceAbsentAfter is how long a watched device must stay silent before
	// it counts as away. Generous on purpose: phones park their radio for
	// minutes at a time, and a flapping presence signal is worse than a slow
	// one.
	presenceAbsentAfter = 10 * time.Minute
	// presenceCheckEvery is the tracker's polling interval. Arrival is
	// detected within one tick of the device's first packet.
	presenceCheckEvery = 30 * time.Second
)

// spawnPresence runs the arrive/leave tracker for watched devices. State
// transitions are persisted and delivered as info alerts, so they show in the
// alert history and reach ntfy — but they bypass the policy cooldown, which
// would otherwise swallow a leave that follows an arrival.
func (a *App) spawnPresence(ctx context.Context, spawn func(string, func()), st *store.Store, disp *notify.Dispatcher) {
	spawn("presence", func() {
		t := time.NewTicker(presenceCheckEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.checkPresence(ctx, st, disp)
			}
		}
	})
}

func (a *App) checkPresence(ctx context.Context, st *store.Store, disp *notify.Dispatcher) {
	devices, err := st.WatchedDevices(ctx)
	if err != nil {
		a.log.Warn("presence: listing watched devices", "err", err)
		return
	}
	now := a.clock()
	for _, d := range devices {
		seen := now.Sub(d.LastSeen) < presenceAbsentAfter
		if seen == d.Present {
			continue
		}
		if err := st.SetDevicePresent(ctx, d.MAC, seen); err != nil {
			a.log.Warn("presence: persisting state", "mac", d.MAC, "err", err)
			continue
		}

		name := d.Name()
		if name == "" {
			name = d.MAC
		}
		title := fmt.Sprintf("%s is back on the network", name)
		detail := fmt.Sprintf("Seen again after being away (silent for %s+).", presenceAbsentAfter)
		if !seen {
			title = fmt.Sprintf("%s left the network", name)
			detail = fmt.Sprintf("No packets for %s (last seen %s).", presenceAbsentAfter, d.LastSeen.Format("15:04"))
		}

		alert := model.Alert{
			Time: now, Detector: "presence", Severity: model.SeverityInfo,
			Source: d.IP, Title: title, Detail: detail, Count: 1,
		}
		stored, err := st.InsertAlert(ctx, alert)
		if err != nil {
			a.log.Warn("presence: storing alert", "err", err)
			stored = alert
		}
		disp.Notify(ctx, stored)
	}
}
