package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type quarantineEntry struct {
	OriginalPath   string `json:"original_path"`
	QuarantinePath string `json:"quarantine_path"`
	SignatureID    string `json:"signature_id"`
	Description    string `json:"description"`
	Time           string `json:"time"`
}

// quarantineFindings moves confirmed-malware files out of the webroot.
// Dry-run by default; force=true performs the moves.
func quarantineFindings(result *ScanResult, root string, force bool) {
	var targets []Finding
	seen := make(map[string]bool)

	all := append([]Finding{}, result.Findings...)
	all = append(all, result.YaraFindings...)
	for _, f := range all {
		if f.Confidence != ConfidenceConfirmed {
			continue
		}
		if strings.HasPrefix(f.FilePath, "DB:") || strings.HasPrefix(f.FilePath, "LOG:") ||
			strings.HasPrefix(f.FilePath, "process:") || strings.Contains(f.FilePath, "_VERSION") {
			continue
		}
		if seen[f.FilePath] {
			continue
		}
		abs := filepath.Join(root, f.FilePath)
		if info, err := os.Stat(abs); err != nil || info.IsDir() {
			continue
		}
		seen[f.FilePath] = true
		targets = append(targets, f)
	}

	if len(targets) == 0 {
		fmt.Println("\n  Quarantine: no confirmed-malware files to quarantine.")
		return
	}

	if !force {
		fmt.Printf("\n%s  QUARANTINE (dry-run — add --force to apply)%s\n", Bold, Reset)
		for _, f := range targets {
			fmt.Printf("  would move: %s %s[%s]%s\n", f.FilePath, Dim, f.SignatureID, Reset)
		}
		fmt.Printf("  %d file(s). Re-run with --quarantine --force to move them.\n", len(targets))
		return
	}

	ts := time.Now().Format("2006-01-02T15-04-05")
	qdir := filepath.Join(root, ".an4scan", "quarantine", ts)
	if err := os.MkdirAll(qdir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "  Quarantine: cannot create %s: %v\n", qdir, err)
		return
	}

	var manifest []quarantineEntry
	moved := 0
	fmt.Printf("\n%s  QUARANTINE%s\n", Bold, Reset)
	for _, f := range targets {
		src := filepath.Join(root, f.FilePath)
		dstName := strings.ReplaceAll(f.FilePath, "/", "__")
		dst := filepath.Join(qdir, dstName)

		if err := os.Rename(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "  failed: %s: %v\n", f.FilePath, err)
			continue
		}
		os.Chmod(dst, 0400)
		moved++
		fmt.Printf("  moved: %s\n", f.FilePath)
		manifest = append(manifest, quarantineEntry{
			OriginalPath: f.FilePath, QuarantinePath: dst,
			SignatureID: f.SignatureID, Description: f.Description,
			Time: time.Now().Format(time.RFC3339),
		})
	}

	if data, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		os.WriteFile(filepath.Join(qdir, "manifest.json"), data, 0600)
	}
	fmt.Printf("  %d file(s) moved to %s (manifest.json written)\n", moved, qdir)
}
