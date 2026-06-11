package main

import "testing"

func TestMagentoVulnerable(t *testing.T) {
	cosmicSting := []string{"2.4.7-p1", "2.4.6-p6", "2.4.5-p8", "2.4.4-p9"}

	cases := []struct {
		version    string
		fixedIn    []string
		vulnerable bool
	}{
		// CosmicSting: fixed in 2.4.6-p6 → p6 is safe, p5 is not
		{"2.4.6-p6", cosmicSting, false},
		{"2.4.6-p5", cosmicSting, true},
		{"2.4.6-p8", cosmicSting, false},
		{"2.4.7", cosmicSting, true},   // 2.4.7-p0 < 2.4.7-p1
		{"2.4.7-p1", cosmicSting, false},
		{"2.4.5-p7", cosmicSting, true},
		{"2.4.5-p8", cosmicSting, false},
		{"2.4.8", cosmicSting, false},  // released after the fix
		{"2.4.3", cosmicSting, true},   // line older than every patched line
		{"2.3.7-p4", cosmicSting, true},
	}

	for _, c := range cases {
		got := magentoVulnerable(parseVersionTuple(c.version), c.fixedIn)
		if got != c.vulnerable {
			t.Errorf("version %s: got vulnerable=%v, want %v", c.version, got, c.vulnerable)
		}
	}
}

func TestCheckMagentoCVEsSkipsM1(t *testing.T) {
	if findings := checkMagentoCVEs("1.9.4.5"); len(findings) != 0 {
		t.Errorf("Magento 1 should not match M2 CVE database, got %d findings", len(findings))
	}
}
