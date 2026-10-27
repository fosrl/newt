//go:build linux

package nativessh

import (
	"os"

	"golang.org/x/sys/unix"
)

// ptyLocalModes returns the ECHO and ICANON flags of the terminal behind the
// PTY master f. On Linux, TCGETS on the master reports the slave's settings.
func ptyLocalModes(f *os.File) (echo, canonical bool, err error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		return false, false, err
	}
	return t.Lflag&unix.ECHO != 0, t.Lflag&unix.ICANON != 0, nil
}
