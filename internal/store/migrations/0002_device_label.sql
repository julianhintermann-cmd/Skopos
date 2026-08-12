-- A user-assigned label for a device. Unlike hostname and vendor, which are
-- discovered from the network and refreshed on every sighting, the label is
-- set only through the UI and is never touched by capture — so a name the
-- operator gives a device sticks for good.
ALTER TABLE devices ADD COLUMN label TEXT NOT NULL DEFAULT '';
