# Architecture

## Data flow

```
            ┌────────────────────────────────────────────────┐
            │                 facts.Collect(root)            │
            │  /proc/sys  /proc/cmdline  /proc/config.gz     │
            │  /proc/modules  /sys/.../vulnerabilities       │
            │  /sys/kernel/security/{lsm,lockdown}           │
            └───────────────────────┬────────────────────────┘
                                    │  *facts.Facts (JSON-serializable snapshot)
              ┌─────────────────────┼──────────────────────┐
              ▼                     ▼                      ▼
   ┌───────────────────┐  ┌──────────────────┐   ┌─────────────────┐
   │ engine.Evaluate   │  │ baseline.Save    │   │ baseline.Diff   │
   │ rules × facts     │  │ snapshot to disk │   │ old vs current  │
   └────────┬──────────┘  └──────────────────┘   └────────┬────────┘
            │ *engine.Report                              │ *baseline.Drift
            ▼                                             ▼
   ┌──────────────────────────────┐          ┌─────────────────────────┐
   │ report: table | json | sarif │          │ report: table | json    │
   └──────────────────────────────┘          └─────────────────────────┘
```

Four packages, one direction of dependency, one shared data model. `facts` knows nothing about rules; `rules` knows nothing about the filesystem; `engine` joins them; `report` only formats. Each seam is independently testable.

## The `--root` design

Every collector resolves paths relative to a configurable root (default `/`). This single decision provides:

1. **Hermetic tests.** `testdata/rootfs-hardened` and `testdata/rootfs-weak` are synthetic `/proc` + `/sys` + `/boot` trees. The full pipeline — collection, evaluation, gating, output — runs in CI on any runner, no privileges, no VMs, deterministic results.
2. **Container deployment.** `docker run -v /:/host:ro kspect scan --root /host` audits the host from an unprivileged, `FROM scratch` container.
3. **Offline analysis.** Point `--root` at a mounted image or a forensic copy of a filesystem to audit boot-time posture (`/boot/config-*`) without booting it.

## Fact collection principles

- **Read-only, always.** No collector opens anything for writing. An auditor that can change the system it audits is a liability.
- **Size-capped reads** (64 KiB/file) — kernel interfaces are small; anything larger is misbehavior we refuse to buffer.
- **Errors are data.** Individual read failures (EPERM, EIO on gated sysctls) are recorded in `Facts.Errors` and surface downstream as `unknown`, never as `fail`.
- **Collect broadly, evaluate narrowly.** The sysctl collector walks the whole `/proc/sys` tree even though rules reference ~30 keys, because baselines and drift detection want the complete surface. Facts are the snapshot format.

## Rule engine

A rule is: metadata (id, title, severity, tags, rationale, remediation, refs) plus one or more **checks**, combined with `any` (default) or `all` semantics.

- `any` models *equivalent controls*: "vsyscall disabled via `CONFIG_LEGACY_VSYSCALL_NONE=y` **or** `vsyscall=none` on the command line".
- `all` models *conjunctions*: "neither `nosmep` nor `nosmap` present".

Deliberately **not** a full expression language. Two combinators cover every rule in the builtin set and every org policy we could design; an expression language would make rulesets unreviewable, and reviewability is the point of policy-as-code.

### Three-state evaluation

| Situation | Result |
|---|---|
| Value present and matches | `pass` |
| Value present and violates | `fail` |
| Key absent on this kernel (e.g. `kernel.io_uring_disabled` pre-6.6) | `unknown` |
| Whole source unavailable (no kconfig exposed, securityfs unmounted) | `unknown` |

`unknown` never counts toward the `--fail-on` gate. This is the primary false-positive control and the reason kspect can run unprivileged, inside containers, and across a heterogenous fleet without generating noise. The summary still reports unknown counts so reduced visibility is itself visible.

## Baseline & drift

A baseline is simply a serialized `Facts` snapshot (mode 0600 — it describes your host in detail). `Diff` compares maps/sets per source and emits typed changes (`added`/`removed`/`changed`).

Noise control: if an entire source is empty on either side (collection failure, permission difference), that source is skipped in the diff — a permission change must not masquerade as 900 removed sysctls.

## Output formats

- **table** — humans; failures sorted first by severity; color only on TTY or `--color always`; info-severity failures render as `NOTE`, because advisory ≠ defect.
- **json** — the full report, stable schema, for pipelines and SIEM ingestion.
- **sarif** — SARIF 2.1.0 with per-rule metadata; only `fail` results are emitted (code scanning is for actionable problems). Severity maps high→`error`, medium/low→`warning`, info→`note`.

## Exit codes

`0` clean · `1` scan failures at/above `--fail-on` · `2` drift · `3` error. Pinned by `TestExitCodeContract`; changing them is a breaking change.

## Why Go, why stdlib-only

- Single static binary: `scp` to any host, drop in an initramfs, run in `FROM scratch`.
- The problem is file reading, string comparison, and JSON — the stdlib does all of it. Zero third-party modules means the supply chain of a tool that runs privileged on every host in a fleet is *the Go toolchain and this repo*, nothing else.
- Rules are JSON rather than YAML purely to preserve that property (and JSON's lack of implicit typing avoids YAML's `no`/`off` footguns in security policy files).
