# Contributing to kspect

Contributions are welcome — new rules most of all, since the ruleset is the product.

## Development setup

Go 1.22+. No other dependencies (and PRs adding third-party modules will be declined — zero-dep is a design guarantee, see `docs/DESIGN_DECISIONS.md` D-2).

```sh
git clone https://github.com/5h4rk-lab/kspect && cd kspect
make build      # bin/kspect
make test       # full suite, includes fixture-based end-to-end tests
make lint       # gofmt + go vet
make demo       # scan the intentionally-weak fixture
```

## Contributing a rule

A rule PR must include:

1. **The rule** in `internal/rules/builtin.json` with every field populated:
   - `id`: next free `KSPECT-<AREA>-NNN`
   - `rationale`: *attacker-centric* — what does violating this control give an adversary? "Best practice" is not a rationale. Cite a CVE or exploit class where one exists.
   - `remediation`: a copy-pasteable command or concrete instruction.
   - `refs`: kernel docs, KSPP, or CIS reference.
   - `tags`: at least one profile tag (`server`, `container-host`, `workstation`) plus topical tags.
2. **Fixture coverage**: update `testdata/rootfs-hardened` so the rule passes and `testdata/rootfs-weak` so it fails (or is `unknown`, if that's the interesting path), and extend the expectation lists in `internal/engine/engine_test.go`.
3. **False-positive analysis** in the PR description: on which kernels/distros is the key absent? Does the rule break a mainstream workload (rootless containers, systemd features)? If a control is legitimate but situational, use severity `info` (rendered as NOTE, never gates by default).

Rules that fire on stock configurations of mainstream distributions need a strong justification — kspect's value depends on findings being credible.

## Code contributions

- Keep the dependency count at zero and collectors strictly read-only.
- Exit codes and the JSON schema are API. Changing them requires a major-version discussion; `TestExitCodeContract` will fail if you break them accidentally.
- New collectors must take the root path, degrade to recorded errors (never panic, never fail the scan), and cap read sizes.
- `gofmt`, `go vet`, and the race detector run in CI; run `make lint test` before pushing.

## Commit / PR conventions

- One logical change per PR; rules and engine changes in separate PRs.
- Reference issues; include before/after output for anything user-visible.
- Update `docs/DESIGN_DECISIONS.md` when a PR makes or reverses an architectural decision.

## Reporting security issues

Please do not open public issues for vulnerabilities in kspect itself — see [SECURITY.md](SECURITY.md).
