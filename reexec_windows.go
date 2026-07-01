//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// reexec restarts newt. On Windows, execve is not available, so outside of
// service mode we start a child process and exit (on success this never
// returns since os.Exit terminates the current process).
//
// When running as a Windows service, spawning a detached child would orphan
// it from the Service Control Manager (the SCM only tracks processes it
// started itself), and os.Exit would end the process without ever reporting
// a clean status transition, making the service look like it crashed. So in
// that case we instead delegate to requestServiceRestart, which asks the SCM
// itself to relaunch the service.
func reexec() error {
	if isWindowsService() {
		return requestServiceRestart()
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start new process: %w", err)
	}
	os.Exit(0)
	return nil // unreachable
}
