// kspect — kernel security posture auditor.
//
// Exit codes (stable contract for CI):
//
//	0  success / no gating failures / no drift
//	1  scan: failing findings at or above --fail-on severity
//	2  diff: drift detected
//	3  runtime or usage error
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/5h4rk-lab/kspect/internal/baseline"
	"github.com/5h4rk-lab/kspect/internal/engine"
	"github.com/5h4rk-lab/kspect/internal/facts"
	"github.com/5h4rk-lab/kspect/internal/report"
	"github.com/5h4rk-lab/kspect/internal/rules"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `kspect — Linux kernel security posture auditor

Usage:
  kspect scan      [flags]           Audit the running kernel against the ruleset
  kspect baseline  [flags] <file>    Snapshot current kernel posture to a file
  kspect diff      [flags] <file>    Compare current posture against a baseline
  kspect rules     [flags]           List rules in the effective ruleset
  kspect version                     Print version

Common flags:
  --root PATH        Filesystem root to audit (default "/"; use /host in containers)
  --rules FILE       Layer a custom JSON ruleset over the builtin rules
  --profile NAME     Deployment profile: server|container-host|workstation|hardened
                     (validated shorthand for --tags)
  --tags a,b         Only evaluate rules carrying any of these tags
  --format FMT       scan: table|json|sarif   diff: table|json   (default table)
  --fail-on SEV      scan: minimum failing severity that sets exit code 1
                     (info|low|medium|high; default low)
  --show-pass        scan: include passing checks in table output
  --ignore PATTERNS  diff: comma-separated kind:key patterns to exclude from
                     drift ('*' suffix matches by prefix), e.g.
                     module:nf_*,sysctl:net.ipv4.ip_forward
  --color MODE       auto|always|never (default auto)

Reducing noise: pick a profile (--profile server), raise the gate
(--fail-on high), and suppress expected drift (diff --ignore kind:key).

Examples:
  kspect scan
  kspect scan --format sarif > kspect.sarif
  kspect scan --profile container-host --fail-on high
  kspect baseline save.json && kspect diff save.json
  docker run --rm -v /:/host:ro ghcr.io/5h4rk-lab/kspect scan --root /host
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 3
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return cmdScan(rest)
	case "baseline":
		return cmdBaseline(rest)
	case "diff":
		return cmdDiff(rest)
	case "rules":
		return cmdRules(rest)
	case "version", "--version", "-v":
		fmt.Println("kspect", version)
		return 0
	case "help", "--help", "-h":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "kspect: unknown command %q\n\n%s", cmd, usage)
		return 3
	}
}

type commonFlags struct {
	root      string
	rulesPath string
	tags      string
	profile   string
	color     string
}

// profiles are the curated deployment profiles every builtin rule is
// tagged with. --profile is a validated alias for --tags: same filter,
// but typos fail loudly instead of silently selecting zero rules.
var profiles = map[string]bool{
	"server": true, "container-host": true, "workstation": true, "hardened": true,
}

func addCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.StringVar(&c.root, "root", "/", "filesystem root to audit")
	fs.StringVar(&c.rulesPath, "rules", "", "path to custom JSON ruleset (layered over builtin)")
	fs.StringVar(&c.tags, "tags", "", "comma-separated rule tags to include")
	fs.StringVar(&c.profile, "profile", "", "deployment profile: server|container-host|workstation|hardened")
	fs.StringVar(&c.color, "color", "auto", "color output: auto|always|never")
	return c
}

func (c *commonFlags) loadRules() ([]rules.Rule, error) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		return nil, fmt.Errorf("builtin ruleset: %w", err)
	}
	if c.rulesPath != "" {
		custom, err := rules.LoadFile(c.rulesPath)
		if err != nil {
			return nil, err
		}
		rs = rules.Merge(rs, custom)
	}
	tags := splitCSV(c.tags)
	if c.profile != "" {
		if !profiles[c.profile] {
			return nil, fmt.Errorf("unknown profile %q (want server|container-host|workstation|hardened)", c.profile)
		}
		tags = append(tags, c.profile)
	}
	if len(tags) > 0 {
		rs = rules.FilterTags(rs, tags)
	}
	return rs, nil
}

func (c *commonFlags) colorEnabled() bool {
	switch c.color {
	case "always":
		return true
	case "never":
		return false
	default:
		fi, err := os.Stdout.Stat()
		return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	}
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	c := addCommon(fs)
	format := fs.String("format", "table", "output format: table|json|sarif")
	failOn := fs.String("fail-on", "low", "minimum failing severity for exit code 1")
	showPass := fs.Bool("show-pass", false, "include passing checks in table output")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("scan takes no positional arguments (got %q)", fs.Args()))
	}
	gate, err := rules.ParseSeverity(*failOn)
	if err != nil {
		return fail(err)
	}
	rs, err := c.loadRules()
	if err != nil {
		return fail(err)
	}
	f := facts.Collect(c.root)
	rep := engine.Evaluate(f, rs)

	opts := report.Options{Color: c.colorEnabled(), ShowPass: *showPass, Version: version}
	switch *format {
	case "table":
		report.WriteTable(os.Stdout, rep, opts)
	case "json":
		if err := report.WriteJSON(os.Stdout, rep); err != nil {
			return fail(err)
		}
	case "sarif":
		if err := report.WriteSARIF(os.Stdout, rep, opts); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("unknown format %q", *format))
	}

	for sev, n := range rep.Summary.FailBySeverity {
		if n > 0 && sev.Rank() >= gate.Rank() {
			return 1
		}
	}
	return 0
}

func cmdBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	c := addCommon(fs)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return 3
	}
	if len(pos) != 1 {
		return fail(fmt.Errorf("baseline requires exactly one output file argument"))
	}
	path := pos[0]
	f := facts.Collect(c.root)
	if err := baseline.Save(f, path); err != nil {
		return fail(err)
	}
	fmt.Fprintf(os.Stderr, "kspect: baseline written to %s (%d sysctls, %d modules, kernel %s)\n",
		path, len(f.Sysctl), len(f.Modules), f.Kernel.Release)
	return 0
}

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	c := addCommon(fs)
	format := fs.String("format", "table", "output format: table|json")
	ignore := fs.String("ignore", "", "comma-separated kind:key drift ignore patterns ('*' suffix matches by prefix)")
	pos, perr := parseInterleaved(fs, args)
	if perr != nil {
		return 3
	}
	if len(pos) != 1 {
		return fail(fmt.Errorf("diff requires exactly one baseline file argument"))
	}
	il, err := baseline.ParseIgnores(splitCSV(*ignore))
	if err != nil {
		return fail(err)
	}
	old, err := baseline.Load(pos[0])
	if err != nil {
		return fail(err)
	}
	cur := facts.Collect(c.root)
	d := baseline.Diff(old, cur, il)

	switch *format {
	case "table":
		report.WriteDriftTable(os.Stdout, d, report.Options{Color: c.colorEnabled()})
	case "json":
		if err := report.WriteDriftJSON(os.Stdout, d); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("unknown format %q", *format))
	}
	if d.HasDrift() {
		return 2
	}
	return 0
}

func cmdRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	c := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("rules takes no positional arguments (got %q)", fs.Args()))
	}
	rs, err := c.loadRules()
	if err != nil {
		return fail(err)
	}
	for _, r := range rs {
		state := ""
		if r.Disabled {
			state = " (disabled)"
		}
		fmt.Printf("%-22s %-7s [%s]%s\n     %s\n", r.ID, r.Severity, strings.Join(r.Tags, ","), state, r.Title)
	}
	fmt.Printf("\n%d rules in effective ruleset\n", len(rs))
	return 0
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "kspect: %v\n", err)
	return 3
}

// parseInterleaved allows flags to appear after positional arguments
// (kspect diff base.json --format json), which the stdlib flag package
// does not support natively. It repeatedly parses, collecting positionals.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
