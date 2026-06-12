package main

import (
	"strings"
	"testing"
)

func TestFindingConfidence(t *testing.T) {
	cases := []struct {
		sig, category, want string
	}{
		{"BD-001", "backdoor", ConfidenceConfirmed},
		{"SF-006", "suspicious", ConfidenceConfirmed},
		{"BD-013", "backdoor", ConfidenceHeuristic},
		{"OB-ENT", "obfuscation", ConfidenceHeuristic},
		{"YARA-somerule", "yara", ConfidenceLikely},
		{"PERM-002", "permissions", ""}, // factual, no confidence
		{"CVE-2024-34102", "cve", ""},
	}
	for _, c := range cases {
		got := findingConfidence(Finding{SignatureID: c.sig, Category: c.category})
		if got != c.want {
			t.Errorf("%s/%s: got %q, want %q", c.sig, c.category, got, c.want)
		}
	}
}

func TestAggregateMassFindings(t *testing.T) {
	var findings []Finding
	for i := 0; i < 100; i++ {
		findings = append(findings, Finding{
			FilePath: "pub/media/file" + strings.Repeat("x", i%5) + ".jpg",
			SignatureID: "PERM-002", Severity: HIGH, Category: "permissions",
			Description: "World-writable file",
		})
	}
	findings = append(findings, Finding{
		FilePath: "app/etc/env.php", SignatureID: "PERM-005",
		Severity: HIGH, Category: "permissions", Description: "env.php world-readable",
	})

	out := aggregateMassFindings(findings, 50)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (1 aggregated + 1 individual), got %d", len(out))
	}
	var agg *Finding
	for i := range out {
		if out[i].SignatureID == "PERM-002" {
			agg = &out[i]
		}
	}
	if agg == nil || !strings.Contains(agg.Description, "(100 files)") {
		t.Errorf("aggregated finding missing or wrong: %+v", agg)
	}
}

func TestNormalizeModuleName(t *testing.T) {
	want := "amastyfeed"
	for _, name := range []string{"Amasty_Feed", "Amasty/Feed", "amasty/feed", "amasty/module-feed"} {
		if got := normalizeModuleName(name); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}
