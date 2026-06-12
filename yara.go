package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sansecio/yargo/ast"
	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

var yaraRulesDir = filepath.Join(os.Getenv("HOME"), ".an4scan", "rules")

// ─── YARA Rule Updater ──────────────────────────────────────────────────────

func yaraUpdate(verbose bool) {
	os.MkdirAll(yaraRulesDir, 0755)

	meta := make(map[string]map[string]interface{})
	metaPath := filepath.Join(yaraRulesDir, "meta.json")
	if data, err := os.ReadFile(metaPath); err == nil {
		json.Unmarshal(data, &meta)
	}

	for _, rs := range YaraRulesets {
		fmt.Printf("  [%s] Downloading %s...\n", rs.Name, rs.Description)
		count, err := downloadRuleset(rs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%s] Error: %v\n", rs.Name, err)
			continue
		}
		fmt.Printf("  [%s] %d rule file(s) installed\n", rs.Name, count)
		meta[rs.Name] = map[string]interface{}{
			"updated": time.Now().Format(time.RFC3339),
			"count":   count,
		}
	}

	fmt.Println("  [magevulndb] Downloading Sansec vulnerable extension database...")
	if err := magevulndbUpdate(verbose); err != nil {
		fmt.Fprintf(os.Stderr, "  [magevulndb] Error: %v\n", err)
	} else {
		fmt.Println("  [magevulndb] Magento 1+2 extension vulnerability lists installed")
		meta["magevulndb"] = map[string]interface{}{
			"updated": time.Now().Format(time.RFC3339),
			"count":   2,
		}
	}

	data, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(metaPath, data, 0644)
}

func downloadRuleset(rs YaraRulesetDef) (int, error) {
	dest := filepath.Join(yaraRulesDir, rs.Name)
	os.RemoveAll(dest)
	os.MkdirAll(dest, 0755)

	client := &http.Client{Timeout: 120 * time.Second}
	req, _ := http.NewRequest("GET", rs.URL, nil)
	req.Header.Set("User-Agent", "an4scan/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if rs.Format == "zip" {
		return downloadZipRuleset(resp.Body, dest, rs)
	}
	return downloadTarGzRuleset(resp.Body, dest, rs)
}

func downloadTarGzRuleset(body io.Reader, dest string, rs YaraRulesetDef) (int, error) {
	gz, err := gzip.NewReader(body)
	if err != nil {
		return 0, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	count := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		rel := stripAndMatch(hdr.Name, rs)
		if rel == "" {
			continue
		}

		outPath := filepath.Join(dest, rel)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		f, err := os.Create(outPath)
		if err != nil {
			continue
		}
		io.Copy(f, tr)
		f.Close()
		count++
	}

	return count, nil
}

func downloadZipRuleset(body io.Reader, dest string, rs YaraRulesetDef) (int, error) {
	tmpFile, err := os.CreateTemp("", "an4scan-*.zip")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, body); err != nil {
		return 0, err
	}

	zr, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rel := stripAndMatch(f.Name, rs)
		if rel == "" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		outPath := filepath.Join(dest, rel)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		out, err := os.Create(outPath)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
		count++
	}

	return count, nil
}

func stripAndMatch(name string, rs YaraRulesetDef) string {
	parts := strings.Split(name, "/")
	if len(parts) <= rs.Strip {
		return ""
	}
	rel := filepath.Join(parts[rs.Strip:]...)

	for _, g := range rs.Globs {
		if matchGlob(rel, g) {
			return rel
		}
	}
	return ""
}

// matchGlob handles patterns like "yara/**/*.yar"
func matchGlob(path, pattern string) bool {
	// Simple case: no **
	if !strings.Contains(pattern, "**") {
		m, _ := filepath.Match(pattern, path)
		return m
	}

	// Split on **
	parts := strings.SplitN(pattern, "**", 2)
	prefix := strings.TrimRight(parts[0], "/")
	suffix := strings.TrimLeft(parts[1], "/")

	// Check prefix
	if prefix != "" && !strings.HasPrefix(path, prefix+"/") && path != prefix {
		return false
	}

	// Check suffix (extension match)
	if suffix != "" {
		// suffix might be "*.yar" or "*.yara"
		m, _ := filepath.Match(suffix, filepath.Base(path))
		return m
	}
	return true
}

func getAllRuleFiles() []string {
	if _, err := os.Stat(yaraRulesDir); err != nil {
		return nil
	}
	var files []string
	filepath.WalkDir(yaraRulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yar" || ext == ".yara" {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func yaraShowStatus() {
	metaPath := filepath.Join(yaraRulesDir, "meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		fmt.Println("  No rulesets downloaded yet. Run: an4scan --update")
		return
	}
	var meta map[string]map[string]interface{}
	json.Unmarshal(data, &meta)

	fmt.Printf("  Rules directory: %s\n\n", yaraRulesDir)
	for name, info := range meta {
		updated := ""
		if u, ok := info["updated"].(string); ok && len(u) >= 19 {
			updated = u[:19]
		}
		count := 0
		if c, ok := info["count"].(float64); ok {
			count = int(c)
		}
		fmt.Printf("  %-20s  %4d files  (updated: %s)\n", name, count, updated)
	}
	total := len(getAllRuleFiles())
	fmt.Printf("\n  Total: %d rule file(s)\n", total)
}

// ─── YARA Auto-Update ──────────────────────────────────────────────────

func yaraAutoUpdate(showProgress, verbose bool) {
	metaPath := filepath.Join(yaraRulesDir, "meta.json")
	data, err := os.ReadFile(metaPath)
	if err == nil {
		var meta map[string]map[string]interface{}
		if json.Unmarshal(data, &meta) == nil && len(meta) > 0 {
			for _, info := range meta {
				if u, ok := info["updated"].(string); ok {
					t, err := time.Parse(time.RFC3339, u)
					if err == nil && time.Since(t) < 24*time.Hour {
						return
					}
				}
				break
			}
		}
	}

	if showProgress {
		fmt.Println("  Updating YARA rulesets...")
	}

	os.MkdirAll(yaraRulesDir, 0755)
	meta := make(map[string]map[string]interface{})
	if data, err := os.ReadFile(metaPath); err == nil {
		json.Unmarshal(data, &meta)
	}

	for _, rs := range YaraRulesets {
		count, err := downloadRuleset(rs)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  [YARA] %s: update failed: %v\n", rs.Name, err)
			}
			continue
		}
		if showProgress {
			fmt.Printf("  [YARA] %s: %d rules\n", rs.Name, count)
		}
		meta[rs.Name] = map[string]interface{}{
			"updated": time.Now().Format(time.RFC3339),
			"count":   count,
		}
	}

	if err := magevulndbUpdate(verbose); err == nil {
		if showProgress {
			fmt.Println("  [magevulndb] extension vulnerability lists updated")
		}
		meta["magevulndb"] = map[string]interface{}{
			"updated": time.Now().Format(time.RFC3339),
			"count":   2,
		}
	} else if verbose {
		fmt.Fprintf(os.Stderr, "  [magevulndb] update failed: %v\n", err)
	}

	mdata, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(metaPath, mdata, 0644)

	if showProgress {
		fmt.Println()
	}
}

// unsupportedYaraMods are string modifiers yargo's parser rejects. Stripping
// them lets many more community rule files parse (at the cost of case-
// sensitivity for nocase strings). The external yara binary handles them
// natively when available.
var unsupportedYaraMods = regexp.MustCompile(`(?i)\b(nocase|wide|xor|private|base64wide)\b`)

// ─── YARA Scanner ────────────────────────────────────────────────────────────
//
// Hybrid engine: if the external `yara` binary is in PATH it is used for full
// fidelity (all rules, all features). Otherwise the embedded pure-Go engine
// (sansecio/yargo) runs — no external dependency, but only rules within yargo's
// supported subset load (built-ins + Sansec Magento rules + simple webshell
// rules; rules using modules/imports/externals are skipped).

// yaraEngineInfo describes which engine ran and how many rules loaded, for
// honest reporting (the embedded engine supports only a subset of YARA).
var yaraEngineInfo string

// yaraEmbeddedUsed is true when the scan fell back to the embedded engine
// because the external `yara` binary was not found — surfaced as a hint so
// the operator can install it for full ruleset coverage.
var yaraEmbeddedUsed bool

func yaraScanner(root, extraRulesPath string, files []string, workers int, verbose bool) ([]Finding, bool) {
	// Collect rule files
	var ruleFiles []string

	// Extra rules
	if extraRulesPath != "" {
		info, err := os.Stat(extraRulesPath)
		if err == nil {
			if info.IsDir() {
				filepath.WalkDir(extraRulesPath, func(path string, d os.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return nil
					}
					ext := strings.ToLower(filepath.Ext(d.Name()))
					if ext == ".yar" || ext == ".yara" {
						ruleFiles = append(ruleFiles, path)
					}
					return nil
				})
			} else {
				ruleFiles = append(ruleFiles, extraRulesPath)
			}
		}
	}

	// Community rulesets
	ruleFiles = append(ruleFiles, getAllRuleFiles()...)

	// Full-fidelity path: external yara binary, if installed
	if yaraBin, err := exec.LookPath("yara"); err == nil {
		yaraEmbeddedUsed = false
		if verbose {
			fmt.Fprintln(os.Stderr, "  [YARA] using external yara binary (full fidelity)")
		}
		return yaraScanExternal(yaraBin, root, ruleFiles, files, verbose)
	}
	yaraEmbeddedUsed = true

	// Parse + validate each source, merge valid rules (dedupe by name)
	p := parser.New()
	merged := &ast.RuleSet{}
	seenRules := make(map[string]bool)
	loaded, failed := 0, 0
	compileOpts := scanner.CompileOptions{SkipInvalidRegex: true}

	addRuleSet := func(rs *ast.RuleSet) {
		if _, err := scanner.CompileWithOptions(rs, compileOpts); err != nil {
			failed++
			return
		}
		for _, r := range rs.Rules {
			if !seenRules[r.Name] {
				seenRules[r.Name] = true
				merged.Rules = append(merged.Rules, r)
			}
		}
		loaded++
	}

	// Built-in rules
	if rs, err := p.Parse(YaraRulesSource); err == nil {
		addRuleSet(rs)
	} else {
		failed++
	}

	for _, rf := range ruleFiles {
		rs, err := p.ParseFile(rf)
		if err != nil {
			// Retry after stripping modifiers yargo doesn't support
			if data, rerr := os.ReadFile(rf); rerr == nil {
				if rs2, serr := p.Parse(unsupportedYaraMods.ReplaceAllString(string(data), "")); serr == nil {
					addRuleSet(rs2)
					continue
				}
			}
			failed++
			continue
		}
		addRuleSet(rs)
	}

	rules, err := scanner.CompileWithOptions(merged, compileOpts)
	if err != nil || rules.NumRules() == 0 {
		if verbose {
			fmt.Fprintf(os.Stderr, "  [YARA] no usable rules (compile error: %v)\n", err)
		}
		return nil, false
	}

	yaraEngineInfo = fmt.Sprintf("embedded engine, %d rules (%d/%d rule files; install 'yara' binary for full rulesets)",
		rules.NumRules(), loaded, loaded+failed)
	if verbose {
		fmt.Fprintf(os.Stderr, "  [YARA] %s\n", yaraEngineInfo)
	}

	// Parallel scan
	var findings []Finding
	var mu sync.Mutex
	fileCh := make(chan string, 256)
	var wg sync.WaitGroup

	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range fileCh {
				info, err := os.Stat(target)
				if err != nil || info.Size() > MaxFileSize || info.Size() == 0 {
					continue
				}
				data, err := os.ReadFile(target)
				if err != nil {
					continue
				}

				var matches scanner.MatchRules
				if err := rules.ScanMem(data, 0, 10*time.Second, &matches); err != nil {
					continue
				}
				if len(matches) == 0 {
					continue
				}

				rel, _ := filepath.Rel(root, target)
				mu.Lock()
				for _, m := range matches {
					sev := strings.ToUpper(m.MetaString("severity", HIGH))
					if _, ok := severityOrder[sev]; !ok {
						sev = HIGH
					}
					findings = append(findings, Finding{
						FilePath:    rel,
						SignatureID: "YARA-" + m.Rule,
						Severity:    sev,
						Category:    "yara",
						Description: "[YARA] " + m.MetaString("description", m.Rule),
					})
				}
				mu.Unlock()
			}
		}()
	}

	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)
	wg.Wait()

	return findings, true
}

// yaraScanExternal scans using the system yara binary: compile each ruleset to
// a temp file once, then scan all targets against each compiled ruleset.
func yaraScanExternal(yaraBin, root string, ruleFiles, files []string, verbose bool) ([]Finding, bool) {
	// Built-in rules first
	builtinPath := filepath.Join(os.TempDir(), "an4scan-builtin.yar")
	if err := os.WriteFile(builtinPath, []byte(YaraRulesSource), 0644); err == nil {
		defer os.Remove(builtinPath)
		ruleFiles = append([]string{builtinPath}, ruleFiles...)
	}

	var findings []Finding
	loaded, failed := 0, 0

	for _, ruleFile := range ruleFiles {
		// Skip rule files that don't compile (missing modules/externals)
		if err := exec.Command(yaraBin, "-w", "-C", ruleFile).Run(); err != nil {
			failed++
			continue
		}
		loaded++

		// -r recursive, -w no warnings; scan the whole tree once per ruleset
		cmd := exec.Command(yaraBin, "-w", "-r", ruleFile, root)
		out, err := cmd.Output()
		if err != nil || len(out) == 0 {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 || strings.HasPrefix(line, "0x") {
				continue
			}
			ruleName, absPath := parts[0], parts[1]
			rel, _ := filepath.Rel(root, absPath)
			findings = append(findings, Finding{
				FilePath:    rel,
				SignatureID: "YARA-" + ruleName,
				Severity:    HIGH,
				Category:    "yara",
				Description: "[YARA] " + ruleName,
			})
		}
	}

	yaraEngineInfo = fmt.Sprintf("external yara binary, %d rule file(s) loaded, %d skipped", loaded, failed)
	if verbose {
		fmt.Fprintf(os.Stderr, "  [YARA] %s\n", yaraEngineInfo)
	}
	return findings, true
}
