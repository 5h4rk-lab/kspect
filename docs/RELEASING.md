# Release checklist

kspect releases are cut from `main` by pushing a tag. The release workflow
builds binaries, publishes the GitHub release, and pushes the multi-arch
container image to GHCR.

## Before tagging

1. `main` is green in CI (lint, race tests, self-scan, Docker job).
2. `go test ./...` and `make lint` pass locally.
3. `TestExitCodeContract` untouched — the `0/1/2/3` exit codes are a
   public API; any change is a breaking change and needs a major-version
   discussion, not a patch release.
4. New rules follow the bar: attacker-centric `rationale`, copy-pasteable
   `remediation`, at least one `refs` entry, and fixture coverage
   (hardened fixture must stay all-pass/no-unknown; weak fixture exercises
   the failure or unknown path).
5. `docs/ROADMAP.md` updated: shipped items moved, next milestone honest.
6. README examples still match actual CLI output (`make demo`).
7. `CHANGELOG`/release notes drafted (user-visible changes, breaking
   changes called out first).

## Tag and release

```sh
git tag -a v0.X.Y -m "kspect v0.X.Y"
git push origin v0.X.Y
```

The Release workflow then:
- runs tests again,
- builds `dist/kspect_linux_{amd64,arm64}` + `SHA256SUMS`
  (asset names are unversioned so `releases/latest/download/…` URLs in
  the README remain stable),
- creates the GitHub release with generated notes,
- builds and pushes `ghcr.io/5h4rk-lab/kspect:{vX.Y.Z,latest}` for
  linux/amd64 and linux/arm64.

## After the release

1. Verify the documented install path end-to-end on a clean machine:
   `curl -LO .../releases/latest/download/kspect_linux_amd64 && ./kspect version`.
2. Verify the container: `docker run --rm -v /:/host:ro ghcr.io/5h4rk-lab/kspect:vX.Y.Z scan --root /host`.
3. Spot-check the SARIF upload path in a scratch repo if report code changed.
4. Update the website if flags or output formats changed.
