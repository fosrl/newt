//go:build !windows && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package nativessh

import (
	"errors"
	"os"
)

func ptyLocalModes(_ *os.File) (echo, canonical bool, err error) {
	return false, false, errors.New("terminal modes not supported on this platform")
}
