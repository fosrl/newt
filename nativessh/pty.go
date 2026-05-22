package nativessh

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// PTYSession is a running shell process attached to a PTY.
// It implements io.ReadWriteCloser so it can be bridged to any transport.
type PTYSession struct {
	ptmx *os.File
	cmd  *exec.Cmd
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

// Close closes the PTY and waits for the child process to exit.
func (p *PTYSession) Close() error {
	err := p.ptmx.Close()
	_ = p.cmd.Wait()
	return err
}
