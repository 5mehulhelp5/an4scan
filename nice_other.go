//go:build !linux

package main

import "syscall"

// setLowPriority lowers CPU priority. I/O priority classes are Linux-only.
func setLowPriority() {
	syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
}
