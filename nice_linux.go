//go:build linux

package main

import (
	"runtime"
	"syscall"
)

// setLowPriority puts the process (and its children: yara, mysql) at the
// lowest CPU and disk I/O priority — equivalent to nice -n 19 ionice -c3.
func setLowPriority() {
	syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)

	// ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << 13)
	ioprioSetNr := map[string]uintptr{"amd64": 251, "arm64": 30}[runtime.GOARCH]
	if ioprioSetNr != 0 {
		const ioprioWhoProcess = 1
		const ioprioClassIdle = 3
		syscall.Syscall(ioprioSetNr, ioprioWhoProcess, 0, ioprioClassIdle<<13)
	}
}
