package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// magevulndb is Sansec's actively-maintained CSV database of vulnerable
// Magento extensions: https://github.com/sansecio/magevulndb
var magevulndbDir = filepath.Join(os.Getenv("HOME"), ".an4scan", "magevulndb")

var magevulndbFiles = map[string]string{
	"magento1-vulnerable-extensions.csv": "https://raw.githubusercontent.com/sansecio/magevulndb/master/magento1-vulnerable-extensions.csv",
	"magento2-vulnerable-extensions.csv": "https://raw.githubusercontent.com/sansecio/magevulndb/master/magento2-vulnerable-extensions.csv",
}

func magevulndbUpdate(verbose bool) error {
	os.MkdirAll(magevulndbDir, 0755)
	client := &http.Client{Timeout: 30 * time.Second}

	var lastErr error
	for name, url := range magevulndbFiles {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "an4scan/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		os.WriteFile(filepath.Join(magevulndbDir, name), data, 0644)
		if verbose {
			fmt.Fprintf(os.Stderr, "  [magevulndb] %s updated (%d bytes)\n", name, len(data))
		}
	}
	return lastErr
}

type magentoVuln struct {
	Module  string // Vendor_Module
	FixedIn string // empty = no fix available
	Ref     string
}

func loadMagevulndb(magentoMajor int) []magentoVuln {
	name := "magento2-vulnerable-extensions.csv"
	if magentoMajor == 1 {
		name = "magento1-vulnerable-extensions.csv"
	}
	f, err := os.Open(filepath.Join(magevulndbDir, name))
	if err != nil {
		return nil
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var vulns []magentoVuln
	first := true
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if first { // header
			first = false
			continue
		}
		if len(rec) < 2 {
			continue
		}
		module := strings.TrimSuffix(strings.TrimSpace(rec[0]), "?")
		ref := ""
		if len(rec) >= 4 {
			ref = strings.TrimSpace(rec[3])
		}
		vulns = append(vulns, magentoVuln{
			Module:  module,
			FixedIn: strings.TrimSpace(rec[1]),
			Ref:     ref,
		})
	}
	return vulns
}

// normalizeModuleName makes "Amasty_Feed", "Amasty/Feed", "amasty/feed" and
// "amasty/module-feed" comparable.
func normalizeModuleName(name string) string {
	n := strings.ToLower(name)
	n = strings.ReplaceAll(n, "module-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.ReplaceAll(n, "/", "")
	n = strings.ReplaceAll(n, "-", "")
	return n
}

func checkMagevulndb(plugins []PluginInfo, magentoMajor int) []PluginFinding {
	vulns := loadMagevulndb(magentoMajor)
	if len(vulns) == 0 {
		return nil
	}

	byName := make(map[string]magentoVuln, len(vulns))
	for _, v := range vulns {
		byName[normalizeModuleName(v.Module)] = v
	}

	var findings []PluginFinding
	for _, p := range plugins {
		v, ok := byName[normalizeModuleName(p.Name)]
		if !ok {
			continue
		}

		if v.FixedIn == "" {
			// Known vulnerable, no fix released
			findings = append(findings, PluginFinding{
				Plugin: p.Name, Version: p.Version,
				CVEID: "MAGEVULNDB", Severity: HIGH,
				Description: "Known vulnerable extension, no fix available (Sansec magevulndb)",
				Fix:         "Remove or replace the extension. " + v.Ref,
			})
			continue
		}

		if p.Version == "" {
			continue // can't compare
		}
		if versionLess(parseVersionTuple(p.Version), parseVersionTuple(v.FixedIn)) {
			findings = append(findings, PluginFinding{
				Plugin: p.Name, Version: p.Version,
				CVEID: "MAGEVULNDB", Severity: HIGH,
				Description: "Known vulnerable extension version (Sansec magevulndb)",
				Fix:         "Update to " + v.FixedIn + "+. " + v.Ref,
			})
		}
	}
	return findings
}
