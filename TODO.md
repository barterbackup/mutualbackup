# Source-review TODO

Source-only defect list. Resolved findings have been removed; this file
contains only high-confidence defects in behavior already implemented. Roadmap
work such as Tor, DHT replacement, hole punching, link-freeze, watchers,
repair, GC, and multiple parity volumes remains intentionally omitted.

## P0 — protection can be lost or falsely reported

## P1 — correctness, durability, availability, and resource bounds

- [ ] **Use an indexed persistent anchor/volume locator in the sector hot
  path.** The supposedly stable locator stores only `st_dev` and an absolute
  volume-root hint (`crates/mb-store/src/anchor.rs:98-104,477-494`), so a
  remount at a new path or device number makes an intact anchor undiscoverable.
  After a simpler parent rename, every 64 KiB sector open independently walks
  the complete filesystem and never caches the resolved area
  (`anchor.rs:113-118,521-553`;
  `crates/mb-node/src/snapshot.rs:902-928`). Resolve a persistent authenticated
  volume/area UUID once through local catalog state, persist the new path hint,
  and never perform a full-volume search per sector.
