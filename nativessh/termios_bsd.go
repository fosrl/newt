//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package nativessh

import (
	"os"

	"golang.org/x/sys/unix"
)

// ptyLocalModes returns the ECHO and ICANON flags of the terminal behind the
// PTY master f. On BSDs the master and slave share one termios.
func ptyLocalModes(f *os.File) (echo, canonical bool, err error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if err != nil {
		return false, false, err
	}
	return t.Lflag&unix.ECHO != 0, t.Lflag&unix.ICANON != 0, nil
}
