package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runCronScan: silent scheduled mode. Only reports findings that are NEW
// compared to the previous saved scan; always saves the current scan as the
// new baseline. Returns the exit code.
func runCronScan(result *ScanResult, sitePath, webhook string) int {
	prevPath := findPreviousScan(sitePath)

	// First run: save baseline, stay silent
	if prevPath == "" {
		if _, err := saveScanResult(result, sitePath); err != nil {
			fmt.Fprintf(os.Stderr, "an4scan cron: cannot save baseline for %s: %v\n", sitePath, err)
			return 1
		}
		fmt.Printf("an4scan cron: baseline saved for %s (%d findings) — future runs alert on new findings only\n",
			sitePath, result.Summary.TotalFindings)
		return 0
	}

	diff, err := diffScans(result, prevPath)
	saveScanResult(result, sitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "an4scan cron: diff failed for %s: %v\n", sitePath, err)
		return 1
	}

	if diff.Summary.NewCount == 0 {
		return 0 // nothing new: stay silent
	}

	// New findings: report
	fmt.Printf("\nan4scan cron: %d NEW finding(s) on %s\n", diff.Summary.NewCount, sitePath)
	printDiffReport(diff)

	if webhook != "" {
		sendWebhook(webhook, sitePath, result, diff)
	}

	exitCode := 0
	for _, f := range diff.NewFindings {
		if f.Severity == CRITICAL {
			return 2
		}
		if f.Severity == HIGH {
			exitCode = 1
		}
	}
	for _, pf := range diff.NewPluginVulns {
		if pf.Severity == CRITICAL {
			return 2
		}
		exitCode = 1
	}
	return exitCode
}

func sendWebhook(url, sitePath string, result *ScanResult, diff *DiffResult) {
	hostname, _ := os.Hostname()
	payload := map[string]interface{}{
		"host":          hostname,
		"scan_path":     sitePath,
		"cms":           result.CMSInfo,
		"time":          time.Now().Format(time.RFC3339),
		"new_count":     diff.Summary.NewCount,
		"new_findings":  diff.NewFindings,
		"new_plugin_vulns": diff.NewPluginVulns,
		"summary":       result.Summary,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "an4scan cron: webhook failed: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "an4scan cron: webhook returned HTTP %d\n", resp.StatusCode)
	} else {
		fmt.Printf("an4scan cron: webhook notified (%s)\n", url)
	}
}
