package main

import (
	"fmt"
	"sort"
	"strings"
)

// confirmedSigs are patterns that are malware with near-certainty when matched.
var confirmedSigs = map[string]bool{
	// eval/exec of user input or decode chains
	"BD-001": true, "BD-002": true, "BD-003": true, "BD-004": true,
	"BD-005": true, "BD-006": true, "BD-007": true, "BD-011": true,
	"ML-001": true, "ML-002": true,
	// Known skimmer domains / malware function names
	"CC-003": true, "MG-005": true,
	// PHP in image is context-verified (printable run + dangerous token)
	"SF-006": true,
	// Reverse shells, exploits, miners
	"PROC-001": true, "PROC-002": true, "PROC-003": true, "PROC-005": true,
	"PROC-009": true, "PROC-010": true, "PROC-011": true, "PROC-012": true,
}

// heuristicSigs are generic patterns that often match legitimate code.
var heuristicSigs = map[string]bool{
	"BD-008": true, "BD-009": true, "BD-010": true, "BD-012": true,
	"BD-013": true, "BD-014": true, "BD-015": true,
	"OB-001": true, "OB-002": true, "OB-003": true, "OB-004": true,
	"OB-005": true, "OB-006": true, "OB-007": true, "OB-008": true,
	"OB-ENT": true,
	"SF-001": true, "SF-002": true, "SF-003": true, "SF-004": true, "SF-005": true,
	"CC-001": true, "CC-002": true, "CC-004": true, "CC-005": true,
	"CC-006": true, "CC-007": true,
	"MG-001": true, "MG-002": true, "MG-003": true, "MG-004": true,
	"MG-006": true, "MG-007": true, "MG-008": true,
	"ML-003": true, "ML-004": true,
	"FO-001": true, "FO-002": true, "FO-003": true,
	"SV-001": true, "SV-002": true, "SV-003": true, "SV-004": true,
	"PROC-004": true, "PROC-006": true, "PROC-007": true, "PROC-008": true,
	"PROC-013": true, "PROC-NET": true,
}

// malwareCategories are finding categories where a confidence level applies
// (vs. factual findings like permissions, CVE matches, mtime).
var malwareCategories = map[string]bool{
	"backdoor": true, "skimmer": true, "obfuscation": true, "suspicious": true,
	"magento": true, "file_operation": true, "server": true, "db_injection": true,
	"yara": true, "reverse_shell": true, "rootkit": true, "exploit": true,
	"crypto_miner": true, "c2_connection": true, "wordpress": true, "prestashop": true,
}

func findingConfidence(f Finding) string {
	if !malwareCategories[f.Category] {
		return ""
	}
	if confirmedSigs[f.SignatureID] {
		return ConfidenceConfirmed
	}
	if heuristicSigs[f.SignatureID] {
		return ConfidenceHeuristic
	}
	return ConfidenceLikely
}

func setConfidence(findings []Finding) {
	for i := range findings {
		if findings[i].Confidence == "" {
			findings[i].Confidence = findingConfidence(findings[i])
		}
	}
}

// aggregateMassFindings collapses groups of identical-signature findings that
// exceed threshold into a single summary finding (one line instead of 40k).
func aggregateMassFindings(findings []Finding, threshold int) []Finding {
	bySig := make(map[string][]Finding)
	var order []string
	for _, f := range findings {
		if _, seen := bySig[f.SignatureID]; !seen {
			order = append(order, f.SignatureID)
		}
		bySig[f.SignatureID] = append(bySig[f.SignatureID], f)
	}

	var out []Finding
	for _, sig := range order {
		group := bySig[sig]
		if len(group) <= threshold {
			out = append(out, group...)
			continue
		}

		// Count by top-level directory to show where the mass is
		dirCount := make(map[string]int)
		for _, f := range group {
			parts := strings.SplitN(f.FilePath, "/", 3)
			top := parts[0]
			if len(parts) > 1 {
				top = parts[0] + "/" + parts[1]
			}
			dirCount[top]++
		}
		type dc struct {
			Dir   string
			Count int
		}
		var dirs []dc
		for d, c := range dirCount {
			dirs = append(dirs, dc{d, c})
		}
		sort.Slice(dirs, func(i, j int) bool { return dirs[i].Count > dirs[j].Count })

		topDirs := ""
		for i, d := range dirs {
			if i >= 3 {
				topDirs += fmt.Sprintf(", +%d other dirs", len(dirs)-3)
				break
			}
			if i > 0 {
				topDirs += ", "
			}
			topDirs += fmt.Sprintf("%s (%d)", d.Dir, d.Count)
		}

		examples := ""
		for i := 0; i < 3 && i < len(group); i++ {
			if i > 0 {
				examples += ", "
			}
			examples += group[i].FilePath
		}

		first := group[0]
		out = append(out, Finding{
			FilePath:    dirs[0].Dir + "/",
			SignatureID: first.SignatureID,
			Severity:    first.Severity,
			Category:    first.Category,
			Description: fmt.Sprintf("%s (%d files)", first.Description, len(group)),
			LineContent: "Top dirs: " + topDirs,
			Context:     "Examples: " + examples,
		})
	}
	return out
}
