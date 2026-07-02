// Package facts collects the kernel security posture of a Linux system by
// reading procfs, sysfs, securityfs and the kernel build configuration.
//
// Every collector reads relative to a configurable root path. This has two
// purposes:
//
//  1. Testability: unit tests run against fixture directory trees, so the
//     full pipeline is exercised in CI without a real kernel.
//  2. Deployability: kspect can run inside a container against the host by
//     bind-mounting / (read-only) and passing --root /host.
//
// Collectors never write anywhere. Reads are size-limited and errors on
// individual files are recorded, not fatal: a missing interface produces an
// "unknown" result downstream instead of a false finding.
package facts

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxRead caps how many bytes are read from any single kernel interface file.
const maxRead = 64 * 1024

// Facts is a point-in-time snapshot of the kernel security posture.
// It is the single data model shared by the rule engine, the baseline
// store and the drift differ, and it serializes cleanly to JSON.
type Facts struct {
	CollectedAt time.Time `json:"collected_at"`
	Root        string    `json:"root"`
	Kernel      Kernel    `json:"kernel"`

	// Sysctl maps dotted sysctl keys (kernel.kptr_restrict) to their raw
	// string value, trimmed of trailing whitespace.
	Sysctl map[string]string `json:"sysctl"`

	// Cmdline holds the raw kernel command line and its parsed parameters.
	// Bare flags (e.g. "quiet") map to the empty string.
	CmdlineRaw string            `json:"cmdline_raw"`
	Cmdline    map[string]string `json:"cmdline"`

	// Kconfig maps CONFIG_* options to their value ("y", "m", numbers,
	// quoted strings). Options that are commented out ("is not set") are
	// mapped to "n". Empty when no config source was found.
	Kconfig       map[string]string `json:"kconfig"`
	KconfigSource string            `json:"kconfig_source,omitempty"`

	// Modules is the sorted list of loaded kernel module names.
	Modules []string `json:"modules"`

	// Mitigations maps entries of /sys/devices/system/cpu/vulnerabilities
	// (e.g. "meltdown") to their status line.
	Mitigations map[string]string `json:"mitigations"`

	// SecurityFS holds normalized values from /sys/kernel/security:
	// "lsm" (comma-separated active LSMs) and "lockdown" (none |
	// integrity | confidentiality, extracted from the bracketed value).
	SecurityFS map[string]string `json:"securityfs"`

	// Errors records non-fatal collection problems for transparency.
	Errors []string `json:"errors,omitempty"`
}

// Kernel identifies the running kernel.
type Kernel struct {
	OSType   string `json:"ostype,omitempty"`
	Release  string `json:"release,omitempty"`
	Version  string `json:"version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

// Collect gathers all facts from the filesystem rooted at root
// (normally "/"). It never returns an error for missing kernel
// interfaces; those are recorded in Facts.Errors.
func Collect(root string) *Facts {
	f := &Facts{
		CollectedAt: time.Now().UTC(),
		Root:        root,
		Sysctl:      map[string]string{},
		Cmdline:     map[string]string{},
		Kconfig:     map[string]string{},
		Mitigations: map[string]string{},
		SecurityFS:  map[string]string{},
	}
	f.collectKernelInfo(root)
	f.collectSysctl(root)
	f.collectCmdline(root)
	f.collectKconfig(root)
	f.collectModules(root)
	f.collectMitigations(root)
	f.collectSecurityFS(root)
	return f
}

func (f *Facts) errf(format string, args ...any) {
	f.Errors = append(f.Errors, fmt.Sprintf(format, args...))
}

// readFile reads a single kernel interface file with a size cap and
// returns the trimmed content.
func readFile(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxRead))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n\t "), nil
}

func (f *Facts) collectKernelInfo(root string) {
	read := func(name string) string {
		v, _ := readFile(filepath.Join(root, "proc/sys/kernel", name))
		return v
	}
	f.Kernel = Kernel{
		OSType:   read("ostype"),
		Release:  read("osrelease"),
		Version:  read("version"),
		Hostname: read("hostname"),
		Arch:     read("arch"),
	}
}

// collectSysctl walks /proc/sys and records every readable value.
// Collecting the full tree (rather than only rule-referenced keys) is
// deliberate: baselines and drift detection want the complete surface.
func (f *Facts) collectSysctl(root string) {
	base := filepath.Join(root, "proc/sys")
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip silently
		}
		if d.IsDir() {
			return nil
		}
		v, rerr := readFile(path)
		if rerr != nil {
			return nil // e.g. EIO on write-only or gated sysctls
		}
		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			return nil
		}
		key := strings.ReplaceAll(rel, string(filepath.Separator), ".")
		f.Sysctl[key] = v
		return nil
	})
	if err != nil {
		f.errf("sysctl walk: %v", err)
	}
	if len(f.Sysctl) == 0 {
		f.errf("sysctl: no values collected under %s", base)
	}
}

func (f *Facts) collectCmdline(root string) {
	raw, err := readFile(filepath.Join(root, "proc/cmdline"))
	if err != nil {
		f.errf("cmdline: %v", err)
		return
	}
	f.CmdlineRaw = raw
	for _, tok := range strings.Fields(raw) {
		k, v, found := strings.Cut(tok, "=")
		if !found {
			f.Cmdline[k] = ""
			continue
		}
		f.Cmdline[k] = v
	}
}

// collectKconfig tries /proc/config.gz first, then /boot/config-<release>.
func (f *Facts) collectKconfig(root string) {
	if p := filepath.Join(root, "proc/config.gz"); tryKconfigGz(f, p) {
		f.KconfigSource = "/proc/config.gz"
		return
	}
	if f.Kernel.Release != "" {
		p := filepath.Join(root, "boot", "config-"+f.Kernel.Release)
		if tryKconfigPlain(f, p) {
			f.KconfigSource = "/boot/config-" + f.Kernel.Release
			return
		}
	}
	// Fall back to any /boot/config-* (useful under --root against images).
	matches, _ := filepath.Glob(filepath.Join(root, "boot", "config-*"))
	sort.Strings(matches)
	for _, p := range matches {
		if tryKconfigPlain(f, p) {
			f.KconfigSource = strings.TrimPrefix(p, filepath.Clean(root))
			return
		}
	}
	f.errf("kconfig: no kernel config found (checked /proc/config.gz, /boot/config-*)")
}

func tryKconfigGz(f *Facts, path string) bool {
	fh, err := os.Open(path)
	if err != nil {
		return false
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return false
	}
	defer gz.Close()
	return parseKconfig(f, gz)
}

func tryKconfigPlain(f *Facts, path string) bool {
	fh, err := os.Open(path)
	if err != nil {
		return false
	}
	defer fh.Close()
	return parseKconfig(f, fh)
}

func parseKconfig(f *Facts, r io.Reader) bool {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "CONFIG_"):
			if k, v, ok := strings.Cut(line, "="); ok {
				f.Kconfig[k] = strings.Trim(v, `"`)
				n++
			}
		case strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set"):
			k := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			f.Kconfig[k] = "n"
			n++
		}
	}
	return n > 0
}

func (f *Facts) collectModules(root string) {
	raw, err := readFile(filepath.Join(root, "proc/modules"))
	if err != nil {
		f.errf("modules: %v", err)
		return
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && !seen[fields[0]] {
			seen[fields[0]] = true
			f.Modules = append(f.Modules, fields[0])
		}
	}
	sort.Strings(f.Modules)
}

func (f *Facts) collectMitigations(root string) {
	dir := filepath.Join(root, "sys/devices/system/cpu/vulnerabilities")
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.errf("mitigations: %v", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if v, err := readFile(filepath.Join(dir, e.Name())); err == nil {
			f.Mitigations[e.Name()] = v
		}
	}
}

func (f *Facts) collectSecurityFS(root string) {
	if v, err := readFile(filepath.Join(root, "sys/kernel/security/lsm")); err == nil {
		f.SecurityFS["lsm"] = v
	} else {
		f.errf("securityfs lsm: %v", err)
	}
	if v, err := readFile(filepath.Join(root, "sys/kernel/security/lockdown")); err == nil {
		f.SecurityFS["lockdown"] = parseBracketed(v)
	} else {
		f.errf("securityfs lockdown: %v", err)
	}
}

// parseBracketed extracts the active option from kernel interfaces of the
// form "none [integrity] confidentiality". If no bracket is present the
// trimmed raw value is returned.
func parseBracketed(v string) string {
	if i := strings.Index(v, "["); i >= 0 {
		if j := strings.Index(v[i:], "]"); j > 0 {
			return v[i+1 : i+j]
		}
	}
	return strings.TrimSpace(v)
}
