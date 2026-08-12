package app

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/speedtest"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

const (
	speedtestEvery = 6 * time.Hour
	// speedtestFirstAfter delays the first measurement so it never competes
	// with the startup burst of feeds, restores and reconnecting dashboards.
	speedtestFirstAfter = 2 * time.Minute
	// speedtestAlarmRatio: alert when download falls below this fraction of
	// the recent median.
	speedtestAlarmRatio = 0.5
)

// speedtestFunc runs one measurement and persists it. The API's "run now"
// button and the periodic loop share this closure; demo mode fabricates a
// plausible line instead of consuming real bandwidth.
func (a *App) speedtestFunc(st *store.Store, disp *notify.Dispatcher) func(ctx context.Context) (model.SpeedtestResult, error) {
	runner := speedtest.New(a.clock)
	return func(ctx context.Context) (model.SpeedtestResult, error) {
		var res model.SpeedtestResult
		var err error
		if a.demo {
			res = fakeSpeedtest(a.clock())
		} else {
			res, err = runner.Run(ctx)
			if err != nil {
				return res, err
			}
		}
		stored, err := st.InsertSpeedtest(ctx, res)
		if err != nil {
			return res, err
		}
		a.maybeSpeedAlarm(ctx, st, disp, stored)
		return stored, nil
	}
}

// spawnSpeedtest measures the line on a fixed interval.
func (a *App) spawnSpeedtest(ctx context.Context, spawn func(string, func()), run func(context.Context) (model.SpeedtestResult, error)) {
	spawn("speedtest", func() {
		timer := time.NewTimer(speedtestFirstAfter)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				runCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				if _, err := run(runCtx); err != nil && ctx.Err() == nil {
					a.log.Warn("speedtest", "err", err)
				}
				cancel()
				timer.Reset(speedtestEvery)
			}
		}
	})
}

// maybeSpeedAlarm notifies when the measured download drops far below the
// recent median — the "is my internet broken" push.
func (a *App) maybeSpeedAlarm(ctx context.Context, st *store.Store, disp *notify.Dispatcher, latest model.SpeedtestResult) {
	history, err := st.ListSpeedtests(ctx, 11)
	if err != nil || len(history) < 4 {
		return // not enough context to call anything an anomaly
	}
	var prior []float64
	for _, h := range history {
		if h.ID != latest.ID {
			prior = append(prior, h.DownMbps)
		}
	}
	if len(prior) < 3 {
		return
	}
	sort.Float64s(prior)
	median := prior[len(prior)/2]
	if median > 0 && latest.DownMbps < median*speedtestAlarmRatio {
		disp.System(ctx, model.SeverityWarning, "Internet speed dropped",
			fmt.Sprintf("Download measured at %.0f Mbit/s — the recent median is %.0f Mbit/s.",
				latest.DownMbps, median))
	}
}

// fakeSpeedtest fabricates a plausible measurement for demo mode.
func fakeSpeedtest(now time.Time) model.SpeedtestResult {
	jitter := func(base, spread float64) float64 { return base + (rand.Float64()-0.5)*spread }
	return model.SpeedtestResult{
		Time:      now,
		DownMbps:  jitter(480, 60),
		UpMbps:    jitter(48, 8),
		LatencyMs: jitter(9, 3),
	}
}
