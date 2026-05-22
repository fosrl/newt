package nativessh

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

// PTYSession is a running shell process attached to a PTY.
// It implements io.ReadWriteCloser so it can be bridged to any transport.
type PTYSession struct {
	ptmx     *os.File
	cmd      *exec.Cmd
	waitOnce sync.Once
	exitCode int
}

// findShell returns the path to the best available interactive shell by
// checking preferred shells in order, falling back to /bin/sh.
func findShell() string {
	preferred := []string{"zsh", "bash", "fish", "ksh", "sh"}
	for _, name := range preferred {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return "/bin/sh"
}

// NewPTYSession spawns the best available shell in a PTY.
func NewPTYSession() (*PTYSession, error) {
	shell := findShell()
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}
	return &PTYSession{ptmx: ptmx, cmd: cmd}, nil
}

// Read reads output from the PTY.
func (p *PTYSession) Read(b []byte) (int, error) {
	return p.ptmx.Read(b)
}

// Write writes input to the PTY.
func (p *PTYSession) Write(b []byte) (int, error) {
	return p.ptmx.Write(b)
}

// Resize changes the PTY window size.
func (p *PTYSession) Resize(cols, rows uint16) error {
	return pty.Setsize(p.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

// wait waits for the child process to exit exactly once and records its exit
// code. Safe to call concurrently or multiple times.
func (p *PTYSession) wait() {
	p.waitOnce.Do(func() {
		err := p.cmd.Wait()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				p.exitCode = exitErr.ExitCode()
				return
			}
			p.exitCode = 1
		}
	})
}

// ExitCode waits for the shell process to exit and returns its exit code.
// It is safe to call before or after Close.
func (p *PTYSession) ExitCode() int {
	p.wait()
	return p.exitCode
}

// Close closes the PTY and waits for the child process to exit.
func (p *PTYSession) Close() error {
	err := p.ptmx.Close()
	p.wait()
	return err
}
