-- A device has one identity but often two addresses. Keeping both in a single
-- column meant whichever family sent the last packet won, so a dual-stack
-- machine showed up as "fe80::8f5:45d3:3bc2:b3ea" one minute and
-- "192.168.1.107" the next.
ALTER TABLE devices ADD COLUMN ip6 TEXT NOT NULL DEFAULT '';

-- Move the addresses that are already IPv6 into the new column. A textual
-- colon test is enough: the column only ever held printed netip addresses.
UPDATE devices SET ip6 = ip, ip = '' WHERE instr(ip, ':') > 0;

-- Drop inventory entries that never described a device. Frames addressed to
-- the broadcast or a multicast group carry a link-layer address that belongs
-- to no machine (ff:ff:ff:ff:ff:ff for a subnet broadcast, 01:00:5e:… and
-- 33:33:… for mDNS, SSDP and NDP), and those were filed as neighbours.
-- Anything an operator has touched — named, restricted or watched — is left
-- alone regardless.
DELETE FROM devices
WHERE label = '' AND policy = '' AND watch_presence = 0
  AND (
        mac = ''
     OR mac = '00:00:00:00:00:00'
     OR lower(substr(mac, 2, 1)) IN ('1', '3', '5', '7', '9', 'b', 'd', 'f')
  );

-- Counting how many MACs have claimed an address is now on the write path.
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices (ip);
CREATE INDEX IF NOT EXISTS idx_devices_ip6 ON devices (ip6);
