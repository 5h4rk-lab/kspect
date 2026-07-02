# kspect

**Linux kernel security posture auditing and drift detection — one static binary, zero dependencies.**

**Website:** https://5h4rk.me/kspect/

kspect audits the *running* kernel's security posture (sysctls, boot parameters, kernel config, loaded modules, CPU vulnerability mitigations, active LSMs, lockdown state), explains every finding with a rationale and a concrete fix, and detects configuration drift against saved baselines. It is built for CI gates, fleet auditing, and incident-response triage — not just one-off checks.

```
$ kspect scan
FAIL HIGH    KSPECT-SYSCTL-003    Unprivileged BPF disabled
     observed: sysctl kernel.unprivileged_bpf_disabled = "0"
     expected: sysctl kernel.unprivileged_bpf_disabled in {1, 2}
     fix:      sysctl -w kernel.unprivileged_bpf_disabled=1
FAIL HIGH    KSPECT-MITIG-001     No unmitigated CPU vulnerabilities
     observed: spectre_v2: Vulnerable, IBPB: disabled, STIBP: disabled
     expected: cpu vulnerabilities not containing "Vulnerable"
     fix:      Update the kernel and CPU microcode; remove any mitigation-disabling boot parameters.
...
Summary: 50 checks — 18 fail, 21 pass, 11 unknown (3 high, 10 medium, 4 low, 1 info)
```

## Why kspect

Kernel hardening guidance exists (KSPP, CIS, vendor docs), but *operationalizing* it is still painful:

- **Point-in-time audit tools tell you about the build, not the box.** Checking a kernel's compile-time config misses what actually matters at runtime: a sysctl silently reset by a package upgrade, `mitigations=off` left over from a benchmark, a `dccp` module loaded by an attacker or a curious teammate.
- **General-purpose audit scripts are noisy.** Hundreds of checks, half not applicable, findings without exploit context, and no clean machine output — so nobody wires them into pipelines.
- **Nothing watches for drift.** Hardening decays. The gap between "we hardened this host last quarter" and "it is still hardened today" is where incidents live.

kspect's answers:

| Capability | What it means in practice |
|---|---|
| **Runtime + build-time in one scan** | sysctls, `/proc/cmdline`, kconfig, modules, `/sys/.../vulnerabilities`, LSMs, lockdown |
| **Three-state results** | `pass` / `fail` / `unknown` — missing data is *never* reported as a failure. This is the core false-positive control |
| **Every finding is actionable** | rationale (what an attacker gains) + exact remediation command + references |
| **Baseline & drift** | `kspect baseline` snapshots posture; `kspect diff` fails (exit 2) on any deviation |
| **CI-native** | stable exit codes, `--fail-on` severity gate, JSON, and **SARIF** for GitHub code scanning |
| **Policy as code** | layer your own JSON rules over the builtins; override or disable any rule by ID |
| **Zero dependencies** | pure Go stdlib, static binary, `FROM scratch` container. Minimal supply chain for a tool you run on every host |

## How kspect compares

Complementary tools, different jobs. Use kspect when the question is *"is this kernel configured the way we hardened it, and is it still?"*

|  | kspect | [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker) | [Lynis](https://cisofy.com/lynis/) | [OpenSCAP](https://www.open-scap.org/) | Falco / Tetragon / Tracee |
|---|---|---|---|---|---|
| Scope | Kernel posture: runtime **and** build-time | Kernel build config, cmdline, sysctl | Whole OS audit (kernel is a small slice) | Compliance profiles (XCCDF/OVAL) | Runtime behavior detection (eBPF) |
| Baseline & drift detection | ✅ built in (`diff`, exit 2) | ❌ | ❌ | remediation-oriented, no drift | n/a (event stream) |
| Missing data becomes a failure? | never — three-state `unknown` | mixed | mixed | profile-dependent | n/a |
| CI-native (exit codes, JSON, SARIF) | ✅ all three | JSON | limited | heavy tooling | n/a |
| Custom org policy | JSON overlay, override by ID | limited | plugins (paid tier for policy) | write XCCDF | rule languages |
| Runs as | one static binary / scratch container | Python | shell scripts | daemon + content packages | privileged agent |
| Remediation info per finding | rationale + exact command + refs | recommendation | suggestion | profile fix scripts | n/a |

Not competitors: Falco/Tetragon/Tracee watch what *happens*; kspect audits how the kernel is *configured*. Run both. kernel-hardening-checker goes deeper on kconfig analysis than kspect; kspect adds the runtime half (live sysctls, loaded modules, active mitigations, LSMs), drift, and CI plumbing.

## Install

**Binary release**

```sh
curl -LO https://github.com/5h4rk-lab/kspect/releases/latest/download/kspect_linux_amd64
chmod +x kspect_linux_amd64 && sudo mv kspect_linux_amd64 /usr/local/bin/kspect
```

**From source** (Go 1.22+)

```sh
go install github.com/5h4rk-lab/kspect/cmd/kspect@latest
```

**Container** (audits the host through a read-only bind mount)

```sh
docker run --rm -v /:/host:ro ghcr.io/5h4rk-lab/kspect scan --root /host
```

kspect only reads files. Run it as root for complete coverage (some sysctls and securityfs are root-only); unprivileged runs still work — inaccessible sources simply report `unknown`.

## Usage

```sh
kspect scan                              # audit, human-readable
kspect scan --format json                # machine-readable, SIEM-friendly
kspect scan --format sarif > k.sarif     # upload to GitHub code scanning
kspect scan --profile server             # deployment profile (server|container-host|workstation|hardened)
kspect scan --tags network,kspp          # finer-grained tag filter
kspect scan --fail-on high               # CI gate: exit 1 only on high-severity failures
kspect scan --rules my-org.json          # layer org policy over builtins

kspect baseline golden.json              # snapshot current posture
kspect diff golden.json                  # exit 2 + report if anything drifted
kspect diff golden.json \
  --ignore module:nf_*,sysctl:net.ipv4.ip_forward   # suppress expected churn
kspect rules                             # list the effective ruleset
```

**Exit codes** (stable contract): `0` clean · `1` gated scan failures · `2` drift · `3` error.

### Profiles and noise control

Every builtin rule is tagged with the deployment profiles it applies to. Start scoped, then tighten:

```sh
kspect scan --profile server --fail-on high    # only server-relevant rules, gate on high only
```

- `--profile server|container-host|workstation|hardened` — validated shorthand for `--tags`; an unknown profile is an error instead of silently matching nothing. `hardened` adds advisory defense-in-depth controls (`init_on_free`, `slab_nomerge`, `modules_disabled`) most fleets intentionally skip.
- `--fail-on high` — report everything, but only high-severity failures set exit 1.
- Advisory rules (severity `info`) render as `NOTE` and never gate by default.
- Persistent disagreement with a rule? Override or disable it by ID in a reviewable `--rules` file rather than filtering forever (see [Custom rules](#custom-rules)).
- For drift, see `diff --ignore` below.

### CI gate example

```yaml
- name: Kernel posture gate
  run: |
    kspect scan --profile container-host --fail-on high --format sarif > kspect.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: kspect.sarif
```

### Drift monitoring example

```sh
kspect baseline /var/lib/kspect/golden.json          # once, after hardening
kspect diff /var/lib/kspect/golden.json || alert     # from cron/systemd timer
```

Volatile runtime counters (`fs.file-nr`, `kernel.ns_last_pid`, `kernel.random.boot_id`, conntrack counts, …) are always excluded from drift, so baselines survive reboots and normal operation. For churn specific to your fleet, pass `--ignore kind:key,...` — kinds are `sysctl|cmdline|kconfig|module|mitigation|securityfs|kernel`, and a trailing `*` matches by prefix (e.g. `module:nf_*` for netfilter modules that load on demand). Malformed patterns are an error (exit 3), never silently ignored.

See [`examples/`](examples/) for a systemd timer unit, a custom ruleset, and sample outputs.

## Custom rules

Rules are plain JSON — reviewable in a PR, generated by scripts, diffed like code:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "ORG-001",
      "title": "Org policy: core dumps fully disabled",
      "severity": "medium",
      "tags": ["org"],
      "rationale": "Core files have leaked credentials in prior incidents.",
      "remediation": "sysctl -w kernel.core_pattern=|/bin/false",
      "checks": [
        { "source": "sysctl", "key": "kernel.core_pattern", "op": "contains", "value": "/bin/false" }
      ]
    },
    { "id": "KSPECT-SYSCTL-008", "title": "n/a", "severity": "low", "disabled": true,
      "rationale": "SysRq required by our on-call runbooks.",
      "checks": [{ "source": "sysctl", "key": "kernel.sysrq", "op": "present" }] }
  ]
}
```

Sources: `sysctl`, `kconfig`, `cmdline`, `module`, `mitigation`, `securityfs`. Operators: `equals`, `not_equals`, `one_of`, `contains`, `not_contains`, `present`, `absent`, `min`, `max`. Combine checks with `"match": "any"` (default, models equivalent controls) or `"all"`.

## What kspect is not

- **Not a runtime detection system.** It audits configuration, not behavior. Pair it with Falco/Tetragon/auditd for runtime telemetry.
- **Not a remediation tool.** It prints exact fixes but never modifies the system — auditors should be read-only.
- **Not a compliance checkbox generator.** Rules exist because they change what an attacker can do, and each says how.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — data flow, package layout, the `--root` design
- [Threat model](docs/THREAT_MODEL.md) — what kspect defends against, and its own attack surface
- [Design decisions](docs/DESIGN_DECISIONS.md) — living engineering log: choices, rejected alternatives, lessons
- [Roadmap](docs/ROADMAP.md) · [Release process](docs/RELEASING.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Apache-2.0 — permissive with an explicit patent grant, the standard choice for security tooling intended for broad corporate adoption.
