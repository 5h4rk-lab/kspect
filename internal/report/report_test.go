package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/5h4rk-lab/kspect/internal/engine"
	"github.com/5h4rk-lab/kspect/internal/facts"
	"github.com/5h4rk-lab/kspect/internal/rules"
)

func weakReport(t *testing.T) *engine.Report {
	t.Helper()
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	return engine.Evaluate(facts.Collect("../../testdata/rootfs-weak"), rs)
}

func TestSARIFStructure(t *testing.T) {
	rep := weakReport(t)
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, rep, Options{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatal("bad SARIF envelope")
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "kspect" {
		t.Error("missing tool name")
	}
	if len(run.Results) != rep.Summary.Fail {
		t.Errorf("SARIF results = %d, want fail count %d", len(run.Results), rep.Summary.Fail)
	}
	ruleIDs := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ruleIDs[r.ID] = true
	}
	for _, r := range run.Results {
		if !ruleIDs[r.RuleID] {
			t.Errorf("result references undeclared rule %s", r.RuleID)
		}
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s missing location (required by GitHub code scanning)", r.RuleID)
		}
		if r.Message.Text == "" {
			t.Errorf("result %s has empty message", r.RuleID)
		}
	}
}

func TestTableOutput(t *testing.T) {
	rep := weakReport(t)
	var buf bytes.Buffer
	WriteTable(&buf, rep, Options{Color: false})
	out := buf.String()
	for _, want := range []string{"FAIL", "KSPECT-SYSCTL-001", "observed:", "fix:", "Summary:"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q", want)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("ANSI codes emitted with color disabled")
	}
}

func TestJSONOutputStable(t *testing.T) {
	rep := weakReport(t)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var decoded engine.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Summary.Total != rep.Summary.Total {
		t.Error("JSON roundtrip lost summary")
	}
}
