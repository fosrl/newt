//go:build windows

package browsergateway

import (
	"context"
	"errors"

	"github.com/coder/websocket"
)

// serveNativeSSHSession is not supported on Windows.
func serveNativeSSHSession(_ context.Context, _ *websocket.Conn, _ nativeSSHConn) error {
	return errors.New("native SSH is not supported on Windows")
}
