# Threat model

Two questions: what threats does kspect help defend against, and what is kspect's own attack surface.

## 1. Threats kspect addresses

kspect is a **preventive/detective configuration control**. It does not stop exploitation at runtime; it reduces the exploitable surface and detects when that reduction erodes.

### T1 — Local privilege escalation via kernel exploitation
The dominant modern LPE path: an unprivileged process (often inside a container) reaches a kernel bug through an exposed interface. Rules directly attack the preconditions:
- **Reachability:** unprivileged eBPF (`SYSCTL-003`, `KCONFIG-008`), io_uring (`SYSCTL-018`), userfaultfd (`SYSCTL-010`), obscure protocol modules DCCP/RDS/TIPC/SCTP (`MODULE-00x`), TTY line-discipline autoload (`SYSCTL-016`), unprivileged user namespaces (advisory `SYSCTL-022`).
- **Exploitation aids:** kernel pointer leaks (`SYSCTL-001/002/007`), disabled KASLR (`CMDLINE-002`, `KCONFIG-001`), NULL-page mapping (`SYSCTL-017`), slab determinism (`CMDLINE-005`, `KCONFIG-006`), missing stack protector / usercopy hardening (`KCONFIG-002/004`).

### T2 — Cross-boundary hardware attacks
Transient-execution vulnerabilities (Spectre/Meltdown/MDS/Retbleed...) break user↔kernel and guest↔host isolation. `MITIG-001` reads the kernel's own authoritative assessment (`/sys/devices/system/cpu/vulnerabilities`) and fails on any `Vulnerable` entry; `CMDLINE-001/003/004` catch mitigation kill-switches left on the command line.

### T3 — Kernel integrity compromise after root (rootkits)
A root compromise escalating into a persistent kernel implant. Controls: module signing (`KCONFIG-010`), lockdown (`KCONFIG-007`, `LOCKDOWN-001`), kexec disabled (`SYSCTL-005`), `/dev/mem` restricted (`KCONFIG-009`), one-way module-loading disable for appliances (`SYSCTL-023`).

### T4 — Hardening decay (drift)
The quiet failure mode: a kernel upgrade resets a sysctl default, a debugging session leaves `ptrace_scope=0`, an engineer loads a module "temporarily". `kspect baseline` + `kspect diff` turn "we hardened it once" into a continuously verified invariant, with exit-code semantics that plug into cron, systemd timers, or fleet configuration management.

### T5 — Classic local attacks
Symlink/hardlink/FIFO races in `/tmp` (`SYSCTL-011..014`), setuid core-dump leaks (`SYSCTL-015`), same-user process injection via ptrace (`SYSCTL-006`), and a small on-host network set: SYN floods, ICMP-redirect MITM, source routing (`SYSCTL-019..021`).

## 2. kspect's own attack surface

An auditor that runs (often as root) on every host must be held to a higher standard than the hosts it audits.

| Asset / vector | Analysis and mitigation |
|---|---|
| **Privilege of the process** | kspect is strictly read-only: no writes, no netlink, no syscalls beyond open/read/stat on kernel virtual files. It needs no network. It runs unprivileged with reduced coverage (degrades to `unknown`, never crashes). The container image is `FROM scratch`, runs as `nobody`, mounts the host read-only. |
| **Malicious input: kernel interface files** | On a compromised host, `/proc` contents are attacker-influenced. Reads are size-capped (64 KiB); parsers are simple line/field splitters with no recursion or allocation proportional to attacker input beyond the cap. Worst case of hostile input is a wrong report — the classic limitation of any on-host auditor: a kernel-level attacker can lie to it. Point-of-audit integrity, not post-compromise forensics, is the claim. |
| **Malicious input: rule files** | `--rules` files are parsed with `encoding/json` and schema-validated; a hostile ruleset can at most cause wrong findings. Rules contain no executable content — no commands are run, remediation strings are only printed. This is a hard design line: an auditor that executes strings from a policy file is a remote-code-execution feature. |
| **Malicious input: baseline files** | Same: pure JSON decode into typed structs. A tampered baseline yields a wrong drift report, not code execution. Baselines are written mode 0600 because they enumerate host configuration (useful recon), and should be stored with integrity protection if used as a security control. |
| **Supply chain** | Zero third-party dependencies — the compromise surface is the Go toolchain and this repository. CI builds are reproducible-friendly (`-trimpath`, pinned Go version); releases ship SHA-256 checksums. |
| **Output injection** | Observed values are echoed into reports. Table output quotes values via `%q` (escaping control characters, defusing terminal-escape injection from hostile sysctl content); JSON/SARIF encoding escapes structurally. |

## 3. Explicit non-goals

- **Runtime attack detection** — no eBPF probes, no event stream. Pair with Falco/Tetragon/auditd.
- **Post-compromise forensics** — a kernel-resident attacker controls what `/proc` says.
- **Remediation** — kspect prints exact fixes but will never apply them.
- **Offensive capability** — findings state what a control prevents; the ruleset contains no exploit code, PoCs, or bypass instructions.
