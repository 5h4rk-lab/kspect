# Design decisions & engineering log

Living record of architectural decisions, rejected alternatives, lessons learned, and confirmed practices. Update entries in place; append new ones. Format: **D-n** decisions, **L-n** lessons, **P-n** confirmed practices.

---

## Decisions

### D-1 — Product scope: posture auditing + drift, not runtime detection
**Decision.** Audit kernel *configuration* (runtime state + build config) and detect drift. No eBPF probes, no event pipeline.
**Rejected: eBPF runtime monitor.** Falco, Tetragon and Tracee already occupy that space with large teams; a new entrant adds noise, requires per-kernel CO-RE maintenance, and cannot be meaningfully tested without privileged kernels in CI. The unowned gap is *operationalized posture*: three-state results, drift, CI gates, SARIF.
**Rejected: kconfig-only checker.** Excellent prior art exists (kernel-hardening-checker). Build-time config alone misses the runtime reality — the sysctl reset by an upgrade, the module loaded yesterday, `mitigations=off` from a benchmarking session. Runtime + build-time + drift in one binary is the differentiated, defensible scope.

### D-2 — Go with zero third-party dependencies
**Decision.** Pure stdlib Go; rules in JSON, embedded with `go:embed`.
**Why.** The tool runs privileged across fleets: its supply chain should be auditable in one sitting. The problem domain is file reads + string comparison + JSON — stdlib territory. Static binary enables `FROM scratch` images, initramfs use, and `scp`-and-run.
**Rejected: Python.** Simple, but "install an interpreter + venv on every audited host" contradicts the deployment story.
**Rejected: Rust.** Equally valid technically; Go chosen for faster iteration and a larger contributor pool in the ops/security tooling community.
**Rejected: YAML rules (would require a dependency).** JSON keeps zero-dep and avoids YAML's implicit-typing footguns (`no` → false) in security policy files. Cost: no comments in rulesets — mitigated by `rationale` being a schema field.

### D-3 — Root-relative collectors
**Decision.** Every filesystem read resolves against a `--root` prefix.
**Why.** One mechanism yields hermetic CI tests (fixture rootfs trees), containerized host auditing (`-v /:/host:ro`), and offline image analysis. This decision did the most work per line of code in the project.

### D-4 — Three-state results; `unknown` never gates
**Decision.** Missing keys and unavailable sources produce `unknown`, reported but excluded from exit-code gating.
**Why.** Fleet reality: kernels differ in version, config exposure, and the privileges kspect runs with. A tool that reports "FAIL" because `/proc/config.gz` isn't exposed gets uninstalled within a week. Low false positives is the adoption-critical property; visibility gaps are still surfaced (unknown counts in the summary) so they can't hide.

### D-5 — Two check combinators (`any`/`all`), no expression language
**Decision.** Rules combine checks with any-of (equivalent controls) or all-of (conjunctions). Nothing more.
**Rejected: CEL/expression engine.** Power that makes rulesets unreviewable defeats policy-as-code; every builtin rule and every org policy drafted during design fit in two combinators.

### D-6 — Rule overlay by ID
**Decision.** `--rules` layers user rules over builtins; identical ID replaces (enabling override or `disabled: true` suppression), new IDs append.
**Why.** Organizations need to tune severity and silence non-applicable rules *in a reviewable file*, not with per-run CLI flags that drift across invocations.

### D-7 — Stable exit-code contract, pinned by test
**Decision.** `0/1/2/3` (clean / gated findings / drift / error), enforced by `TestExitCodeContract`.
**Why.** CI integrations depend on exit codes more than on any output format; treating them as API prevents accidental breakage.

### D-8 — SARIF output
**Decision.** Emit SARIF 2.1.0 (failures only) alongside JSON.
**Why.** GitHub code scanning ingestion puts kernel posture regressions in the same review surface as application findings — this is what makes security *and* platform teams actually see the results. Passes/unknowns are omitted: code scanning is for actionable problems.

### D-9 — Auditor is strictly read-only; remediation is text
**Decision.** kspect never modifies the system; remediation strings are printed, never executed.
**Why.** A privileged fleet-wide tool that executes strings from policy files is an RCE feature. Read-only is also what makes `-v /:/host:ro` honest.

### D-10 — Info-severity failures render as NOTE
**Decision.** Advisory rules (e.g. user-namespace surface, `modules_disabled`) display `NOTE`, not `FAIL`, and never gate by default.
**Why.** Discovered during fixture testing: a hardened host "failing" advisory checks reads as false positives and erodes trust. JSON semantics unchanged (`status: fail`, `severity: info`) so pipelines can still key on them.

### D-11 — Drift ignore lists: CLI flag, not baseline-embedded (yet)
**Decision.** `diff --ignore kind:key,...` with a `*` prefix glob; volatile runtime counters (per-boot IDs, live counters) are suppressed unconditionally in the differ. Malformed or unknown-kind patterns are a hard error.
**Why.** Fleet-specific churn (on-demand netfilter modules, tuned sysctls) must be suppressible without editing baselines, and the invocation lives in the systemd unit or CI config where it is itself reviewed. Silent acceptance of a typo'd pattern would mask real drift — the failure mode a drift tool exists to prevent — hence strict validation.
**Rejected (for now): ignore lists stored inside baseline files.** The baseline file is currently a raw `facts.Facts` snapshot; embedding policy in it requires a versioned wrapper format and a migration story. Deferred to a baseline-format RFC rather than rushed into v0.2.
**Rejected: full regex patterns.** Prefix globs cover the observed use cases (module families, sysctl subtrees) and stay reviewable at a glance.

---

## Lessons learned

### L-1 — Any-of semantics silently broke conjunction rules
The SMEP/SMAP rule ("`nosmep` absent AND `nosmap` absent") initially passed on a host with `nosmep` set, because the engine's any-of logic accepted the passing `nosmap` check. Caught by scanning the weak fixture and diffing expectations. Fix: explicit `match: all` (D-5). Lesson: adversarial fixtures that *should* fail specific rules are as important as clean ones; every rule now has a fixture exercising its failure path or its unknown path.

### L-2 — stdlib `flag` stops at the first positional argument
`kspect diff base.json --format json` silently treated `--format json` as positionals. Fixed with an interleaved parse loop. Lesson: test CLIs with flags in the order users actually type them.

### L-3 — Drift diffing needs source-level noise suppression
First diff implementation reported hundreds of "removed" sysctls when comparing a root-collected baseline against an unprivileged run. Fix: skip a source entirely in the diff when it's empty on either side. Lesson: permission asymmetry is a normal operating condition, not an edge case.

### L-4 — Absent keys carry meaning, and the meaning is op-dependent
`kernel.io_uring_disabled` missing means "old kernel" (→ unknown), but a missing cmdline flag under `not_equals` means "the dangerous value is not set" (→ pass), and a missing key under `absent` is itself a pass. The lookup layer must distinguish "source unavailable" from "key not present" — collapsing them produces either false positives or false negatives depending on the rule.

## Confirmed practices

- **P-1** Fixture-driven end-to-end tests (two synthetic rootfs trees: hardened → all pass, weak → known failures + known unknowns) catch rule-logic bugs that unit tests of the engine miss.
- **P-2** Every rule ships with `rationale` (attacker-centric: what does violating this give an adversary) and `remediation` (copy-pasteable command). Enforced by test.
- **P-3** Observed values are echoed with `%q` in terminal output — kernel interfaces on a hostile host are untrusted input; escape them.
- **P-4** CI includes a self-scan of the runner's real kernel, gated on "tool completes and output parses", not on findings — real-kernel smoke coverage without asserting the runner's posture.
