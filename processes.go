package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	PID     int
	UID     int
	User    string
	Cmdline string
	Exe     string
	Name    string
}

type ProcessPattern struct {
	ID          string
	Severity    string
	Category    string
	Description string
	Match       func(p ProcessInfo) bool
}

var processPatterns = []ProcessPattern{
	{
		ID:          "PROC-001",
		Severity:    CRITICAL,
		Category:    "reverse_shell",
		Description: "Reverse shell (pty.spawn)",
		Match: func(p ProcessInfo) bool {
			return strings.Contains(p.Cmdline, "pty.spawn") ||
				strings.Contains(p.Cmdline, "pty;pty")
		},
	},
	{
		ID:          "PROC-002",
		Severity:    CRITICAL,
		Category:    "reverse_shell",
		Description: "Reverse shell (bash -i /dev/tcp)",
		Match: func(p ProcessInfo) bool {
			return (strings.Contains(p.Cmdline, "bash -i") && strings.Contains(p.Cmdline, "/dev/tcp")) ||
				(strings.Contains(p.Cmdline, "bash -i") && strings.Contains(p.Cmdline, "/dev/udp"))
		},
	},
	{
		ID:          "PROC-003",
		Severity:    CRITICAL,
		Category:    "reverse_shell",
		Description: "Reverse shell (netcat)",
		Match: func(p ProcessInfo) bool {
			cmd := p.Cmdline
			return (strings.Contains(cmd, "nc ") || strings.Contains(cmd, "ncat ")) &&
				(strings.Contains(cmd, "-e ") || strings.Contains(cmd, "-c "))
		},
	},
	{
		ID:          "PROC-004",
		Severity:    CRITICAL,
		Category:    "rootkit",
		Description: "Fake kernel thread (user-space process masquerading as kernel thread)",
		Match: func(p ProcessInfo) bool {
			if p.UID == 0 {
				return false
			}
			name := p.Name
			if name == "" {
				name = p.Cmdline
			}
			fakeKernelRe := regexp.MustCompile(`^\[.*\]$`)
			if fakeKernelRe.MatchString(name) {
				return true
			}
			if strings.HasPrefix(name, "kworker") || strings.HasPrefix(name, "kthread") ||
				strings.HasPrefix(name, "ksoftirqd") || strings.HasPrefix(name, "migration/") {
				return true
			}
			return false
		},
	},
	{
		ID:          "PROC-005",
		Severity:    CRITICAL,
		Category:    "exploit",
		Description: "Privilege escalation exploit",
		Match: func(p ProcessInfo) bool {
			cmd := p.Cmdline
			return strings.Contains(cmd, "/var/tmp/exp") ||
				strings.Contains(cmd, "/tmp/exp ") ||
				strings.HasSuffix(cmd, "/tmp/exp")
		},
	},
	{
		ID:          "PROC-006",
		Severity:    HIGH,
		Category:    "backdoor",
		Description: "Hidden temp file execution",
		Match: func(p ProcessInfo) bool {
			hiddenTmpRe := regexp.MustCompile(`/tmp/\.[a-zA-Z]`)
			return hiddenTmpRe.MatchString(p.Cmdline)
		},
	},
	{
		ID:          "PROC-007",
		Severity:    HIGH,
		Category:    "backdoor",
		Description: "PHP running from /tmp (likely backdoor)",
		Match: func(p ProcessInfo) bool {
			return strings.Contains(p.Cmdline, "php") &&
				(strings.Contains(p.Cmdline, "/tmp/") || strings.Contains(p.Cmdline, "/var/tmp/"))
		},
	},
	{
		ID:          "PROC-008",
		Severity:    HIGH,
		Category:    "exploit",
		Description: "SUID preserved shell (sh -p)",
		Match: func(p ProcessInfo) bool {
			return p.Cmdline == "sh -p" || strings.HasSuffix(p.Cmdline, " sh -p") ||
				strings.Contains(p.Cmdline, "sh -p ")
		},
	},
	{
		ID:          "PROC-009",
		Severity:    CRITICAL,
		Category:    "reverse_shell",
		Description: "Socat reverse shell",
		Match: func(p ProcessInfo) bool {
			return strings.Contains(p.Cmdline, "socat") &&
				(strings.Contains(p.Cmdline, "TCP:") || strings.Contains(p.Cmdline, "tcp:")) &&
				(strings.Contains(p.Cmdline, "EXEC:") || strings.Contains(p.Cmdline, "exec:"))
		},
	},
	{
		ID:          "PROC-010",
		Severity:    HIGH,
		Category:    "crypto_miner",
		Description: "Cryptocurrency miner process",
		Match: func(p ProcessInfo) bool {
			cmd := strings.ToLower(p.Cmdline)
			return strings.Contains(cmd, "xmrig") || strings.Contains(cmd, "minerd") ||
				strings.Contains(cmd, "stratum+tcp") || strings.Contains(cmd, "cryptonight") ||
				strings.Contains(cmd, "monero")
		},
	},
	{
		ID:          "PROC-011",
		Severity:    CRITICAL,
		Category:    "reverse_shell",
		Description: "Python socket reverse shell",
		Match: func(p ProcessInfo) bool {
			cmd := p.Cmdline
			return strings.Contains(cmd, "python") &&
				(strings.Contains(cmd, "import socket") || strings.Contains(cmd, "import subprocess") ||
					strings.Contains(cmd, "socket.socket") || strings.Contains(cmd, "subprocess.call"))
		},
	},
	{
		ID:          "PROC-012",
		Severity:    CRITICAL,
		Category:    "reverse_shell",
		Description: "Perl reverse shell",
		Match: func(p ProcessInfo) bool {
			cmd := p.Cmdline
			return strings.Contains(cmd, "perl") &&
				(strings.Contains(cmd, "IO::Socket") || strings.Contains(cmd, "socket(") ||
					(strings.Contains(cmd, "exec") && strings.Contains(cmd, "/bin/")))
		},
	},
	{
		ID:          "PROC-013",
		Severity:    HIGH,
		Category:    "rootkit",
		Description: "LD_PRELOAD hijacking (shared library injection)",
		Match: func(p ProcessInfo) bool {
			return strings.Contains(p.Cmdline, "LD_PRELOAD=")
		},
	},
}

func scanProcesses(verbose bool) []Finding {
	var findings []Finding

	procs := readProcesses(verbose)
	for _, proc := range procs {
		for _, pattern := range processPatterns {
			if pattern.Match(proc) {
				context := fmt.Sprintf("PID=%d UID=%d", proc.PID, proc.UID)
				if proc.User != "" {
					context += " User=" + proc.User
				}
				if proc.Exe != "" && proc.Exe != proc.Cmdline {
					context += " Exe=" + proc.Exe
				}

				findings = append(findings, Finding{
					FilePath:    fmt.Sprintf("process:%d", proc.PID),
					SignatureID: pattern.ID,
					Severity:    pattern.Severity,
					Category:    pattern.Category,
					Description: pattern.Description,
					LineContent: proc.Cmdline,
					Context:     context,
				})
			}
		}
	}

	// Check for suspicious outbound connections
	connFindings := checkSuspiciousConnections(procs, verbose)
	findings = append(findings, connFindings...)

	return findings
}

func readProcesses(verbose bool) []ProcessInfo {
	var procs []ProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Warning: cannot read /proc: %v\n", err)
		}
		return procs
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		proc := ProcessInfo{PID: pid}

		// Read cmdline
		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		proc.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmdlineBytes), "\x00", " "))
		if proc.Cmdline == "" {
			// Kernel thread — read comm instead
			commBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if err != nil {
				continue
			}
			proc.Name = "[" + strings.TrimSpace(string(commBytes)) + "]"
		}

		// Read status for UID and Name
		statusBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err == nil {
			for _, line := range strings.Split(string(statusBytes), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						proc.UID, _ = strconv.Atoi(fields[1])
					}
				}
				if strings.HasPrefix(line, "Name:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 && proc.Name == "" {
						proc.Name = fields[1]
					}
				}
			}
		}

		// Read exe symlink
		exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err == nil {
			proc.Exe = exe
		}

		// Resolve username from /etc/passwd (best effort)
		proc.User = resolveUser(proc.UID)

		procs = append(procs, proc)
	}

	return procs
}

var userCache map[int]string

func resolveUser(uid int) string {
	if userCache == nil {
		userCache = make(map[int]string)
		data, err := os.ReadFile("/etc/passwd")
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 4)
			if len(parts) >= 3 {
				if id, err := strconv.Atoi(parts[2]); err == nil {
					userCache[id] = parts[0]
				}
			}
		}
	}
	return userCache[uid]
}

func checkSuspiciousConnections(procs []ProcessInfo, verbose bool) []Finding {
	var findings []Finding

	// Read /proc/net/tcp for established outbound connections on suspicious ports
	tcpData, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Warning: cannot read /proc/net/tcp: %v\n", err)
		}
		return findings
	}

	// Build PID→process lookup from /proc/*/fd → socket inodes
	// This is expensive, so only do it if we find suspicious connections
	type tcpConn struct {
		LocalPort  int
		RemoteIP   string
		RemotePort int
		Inode      string
		State      string
	}

	suspiciousPorts := map[int]bool{
		4444: true, 4445: true, 5555: true, 6666: true, 6667: true,
		7777: true, 8888: true, 9999: true, 12345: true, 31337: true,
		55555: true, 1234: true, 1337: true, 9001: true, 9002: true,
	}

	var suspConns []tcpConn
	for _, line := range strings.Split(string(tcpData), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] == "sl" {
			continue
		}
		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		remoteAddr := fields[2]
		remoteIP, remotePort := parseProcNetAddr(remoteAddr)
		if suspiciousPorts[remotePort] {
			localAddr := fields[1]
			_, localPort := parseProcNetAddr(localAddr)
			suspConns = append(suspConns, tcpConn{
				LocalPort:  localPort,
				RemoteIP:   remoteIP,
				RemotePort: remotePort,
				Inode:      fields[9],
			})
		}
	}

	if len(suspConns) == 0 {
		return findings
	}

	// Resolve inode → PID
	inodeToPID := make(map[string]int)
	for _, proc := range procs {
		fdDir := fmt.Sprintf("/proc/%d/fd", proc.PID)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") {
				inode := link[8 : len(link)-1]
				inodeToPID[inode] = proc.PID
			}
		}
	}

	pidMap := make(map[int]ProcessInfo)
	for _, p := range procs {
		pidMap[p.PID] = p
	}

	for _, conn := range suspConns {
		desc := fmt.Sprintf("Suspicious outbound connection to %s:%d", conn.RemoteIP, conn.RemotePort)
		context := fmt.Sprintf("LocalPort=%d", conn.LocalPort)

		filePath := "network"
		if pid, ok := inodeToPID[conn.Inode]; ok {
			filePath = fmt.Sprintf("process:%d", pid)
			if p, ok := pidMap[pid]; ok {
				context += fmt.Sprintf(" PID=%d Cmd=%s", pid, p.Cmdline)
			}
		}

		findings = append(findings, Finding{
			FilePath:    filePath,
			SignatureID: "PROC-NET",
			Severity:    HIGH,
			Category:    "c2_connection",
			Description: desc,
			LineContent: fmt.Sprintf("%s:%d → %s:%d (ESTABLISHED)", "local", conn.LocalPort, conn.RemoteIP, conn.RemotePort),
			Context:     context,
		})
	}

	return findings
}

func parseProcNetAddr(hex string) (string, int) {
	parts := strings.Split(hex, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// IP is in little-endian hex
	ipHex := parts[0]
	if len(ipHex) == 8 {
		b0, _ := strconv.ParseUint(ipHex[6:8], 16, 8)
		b1, _ := strconv.ParseUint(ipHex[4:6], 16, 8)
		b2, _ := strconv.ParseUint(ipHex[2:4], 16, 8)
		b3, _ := strconv.ParseUint(ipHex[0:2], 16, 8)
		ip := fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
		port, _ := strconv.ParseUint(parts[1], 16, 16)
		return ip, int(port)
	}

	return "", 0
}
