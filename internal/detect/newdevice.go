package detect

import (
	"fmt"
	"net/netip"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// NewDeviceConfig configures the new-device detector.
type NewDeviceConfig struct {
	Severity model.Severity
}

// NewDevice raises a finding when a previously-unseen device appears on the
// LAN. Unlike the packet-driven detectors it is event-driven: the device
// tracker calls Report when its store reports a first sighting, so there is no
// window or threshold to tune.
type NewDevice struct {
	cfg  NewDeviceConfig
	sink Sink
}

// NewNewDevice creates the detector.
func NewNewDevice(cfg NewDeviceConfig, sink Sink) *NewDevice {
	return &NewDevice{cfg: cfg, sink: sink}
}

// Report is wired to the device tracker's new-device callback.
func (d *NewDevice) Report(mac, ip string) {
	var src netip.Addr
	if a, err := netip.ParseAddr(ip); err == nil {
		src = a
	}
	d.sink.Raise(Finding{
		Detector: "new_device",
		Source:   src,
		Severity: d.cfg.Severity,
		Title:    fmt.Sprintf("New device on the network: %s", mac),
		Detail:   fmt.Sprintf("first seen at %s (MAC %s)", ip, mac),
	})
}
