# Roadmap

Ordered by expected user value. Items marked (RFC) need a design discussion before implementation — open an issue.

## v0.2 — Fleet ergonomics
- `--quiet` (failures only) and `--format ndjson` for log shippers
- `kspect diff --ignore <kind:key,...>` and ignore lists inside baselines (planned churn: interface sysctls, expected module sets)
- Prometheus textfile-collector output (`kspect scan --format prom`) so posture becomes a dashboarded metric
- Ruleset docs generator: render `rules/` to Markdown for policy review

## v0.3 — Deeper collection (still read-only)
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
