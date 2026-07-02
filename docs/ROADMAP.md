# Roadmap

Ordered by expected user value. Items marked (RFC) need a design discussion before implementation — open an issue.

## Shipped in v0.2.0
- `--profile server|container-host|workstation|hardened` — validated deployment-profile filter
- `kspect diff --ignore <kind:key,...>` with `*` prefix globs for fleet-specific churn
- Expanded always-on volatile sysctl suppression (per-boot IDs, runtime counters)
- Multi-arch (amd64/arm64) container image; stable release-asset names
- IPv6 ICMP-redirect and `init_on_free` rules

## v0.3 — Fleet ergonomics & deeper collection (still read-only)
- `--quiet` (failures only) and `--format ndjson` for log shippers
- Ignore lists stored inside baseline files (needs a versioned baseline format — RFC)
- Prometheus textfile-collector output (`kspect scan --format prom`) so posture becomes a dashboarded metric
- Ruleset docs generator: render `rules/` to Markdown for policy review

### Deeper collection
- Boot-time vs runtime divergence: compare `/boot/config-*` of the *newest installed* kernel vs the *running* one (unpatched-but-installed detection)
- `/etc/modprobe.d` blacklist parsing: distinguish "module not loaded" from "module cannot load" (upgrades MODULE-00x from point-in-time to durable)
- Landlock / seccomp availability reporting
- Per-container view (RFC): given a container's seccomp/caps config, report which failing kernel surface rules are actually reachable from it

## v0.4 — Ecosystem
- Ruleset versioning + `kspect rules update` from signed release assets (rules move faster than binaries)
- CIS Distribution-Independent Linux kernel-section mapping tags for compliance teams
- Debian/RPM packages; nix flake
- kubectl plugin / DaemonSet manifest for cluster-wide node auditing with aggregated output

## Explicit non-goals (see THREAT_MODEL.md)
- Runtime detection (eBPF probes, event streams)
- Automatic remediation
- Windows/macOS support
