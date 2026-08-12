-- Presence tracking. watch_presence is the operator's opt-in per device;
-- present is the tracker's last known state, persisted so a restart does not
-- fire spurious arrive/leave notifications for every watched device.
ALTER TABLE devices ADD COLUMN watch_presence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN present INTEGER NOT NULL DEFAULT 0;
