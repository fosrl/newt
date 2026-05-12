package browsergateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/coder/websocket"
	"github.com/creack/pty"
)

// NativeSSHConfig holds configuration for the native PTY/shell mode.
type NativeSSHConfig struct {
	// Shell is the executable to spawn (e.g. /bin/bash). Defaults to /bin/sh.
	Shell string
}

// serveNativeSSHSession handles a WebSocket SSH session by spawning a local
// PTY+shell instead of proxying to an external SSH server. The auth token has
// already been validated at the WebSocket upgrade level, so this function only
// reads (and discards) the initial "auth" frame for protocol compatibility with
// the browser client before starting the shell.
func serveNativeSSHSession(ctx context.Context, ws *websocket.Conn, cfg NativeSSHConfig) error {
	// Read and discard the auth frame (token already validated at HTTP layer).
	_, authBytes, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("read auth message: %w", err)
	}
	var authMsg sshClientMsg
	if err := json.Unmarshal(authBytes, &authMsg); err != nil || authMsg.Type != "auth" {
		return fmt.Errorf("expected auth message, got: %s", authBytes)
	}

	shell := cfg.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	log.Printf("SSH native: spawning %s", shell)

	cmd := exec.CommandContext(ctx, shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	// Start the command with a PTY attached.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		sendSSHError(ctx, ws, fmt.Sprintf("Failed to spawn shell: %v", err))
		return fmt.Errorf("pty start: %w", err)
	}
	defer func() {
		_ = ptmx.Close()
		_ = cmd.Wait()
	}()

	// Cancel context to unblock the WebSocket read loop when the shell exits.
	sessCtx, cancelSess := context.WithCancel(ctx)
	defer cancelSess()

	// Pump PTY output → WebSocket.
	go func() {
		defer cancelSess()
		buf := make([]byte, 4096)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				msg := sshServerMsg{Type: "data", Data: string(buf[:n])}
				b, _ := json.Marshal(msg)
				if writeErr := ws.Write(sessCtx, websocket.MessageText, b); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Pump WebSocket input → PTY stdin / resize.
	for {
		_, msgBytes, readErr := ws.Read(sessCtx)
		if readErr != nil {
			break
		}
		var msg sshClientMsg
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "data":
			if _, writeErr := ptmx.Write([]byte(msg.Data)); writeErr != nil {
				return fmt.Errorf("write pty: %w", writeErr)
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = pty.Setsize(ptmx, &pty.Winsize{
					Cols: uint16(msg.Cols),
					Rows: uint16(msg.Rows),
				})
			}
		}
	}

	return nil
}
