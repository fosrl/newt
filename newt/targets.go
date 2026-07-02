package newt

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
)

func parseTargetData(data interface{}) (TargetData, error) {
	var targetData TargetData
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return targetData, err
	}

	if err := json.Unmarshal(jsonData, &targetData); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
		return targetData, err
	}
	return targetData, nil
}

// parseTargetString parses "listenPort:host:targetPort", handling IPv6 brackets.
func parseTargetString(target string) (int, string, error) {
	firstColon := strings.Index(target, ":")
	if firstColon == -1 {
		return 0, "", fmt.Errorf("invalid target format, no colon found: %s", target)
	}

	listenPortStr := target[:firstColon]
	var listenPort int
	_, err := fmt.Sscanf(listenPortStr, "%d", &listenPort)
	if err != nil {
		return 0, "", fmt.Errorf("invalid listen port: %s", listenPortStr)
	}
	if listenPort <= 0 || listenPort > 65535 {
		return 0, "", fmt.Errorf("listen port out of range: %d", listenPort)
	}

	remainder := target[firstColon+1:]
	host, targetPort, err := net.SplitHostPort(remainder)
	if err != nil {
		return 0, "", fmt.Errorf("invalid host:port format '%s': %w", remainder, err)
	}

	if host == "" {
		return 0, "", fmt.Errorf("empty host in target: %s", target)
	}
	if targetPort == "" {
		return 0, "", fmt.Errorf("empty target port in target: %s", target)
	}

	return listenPort, net.JoinHostPort(host, targetPort), nil
}

func (n *Newt) updateTargets(pm *proxy.ProxyManager, action string, tunnelIP string, proto string, targetData TargetData) error {
	for _, t := range targetData.Targets {
		port, target, err := parseTargetString(t)
		if err != nil {
			logger.Info("Invalid target format: %s (%v)", t, err)
			continue
		}

		switch action {
		case "add":
			processedTarget := target
			if n.config.UpdownScript != "" {
				newTarget, err := n.executeUpdownScript(action, proto, target)
				if err != nil {
					logger.Warn("Updown script error: %v", err)
				} else if newTarget != "" {
					processedTarget = newTarget
				}
			}

			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				if !strings.Contains(err.Error(), "target not found") {
					logger.Error("Failed to remove existing target: %v", err)
				}
			}

			pm.AddTarget(proto, tunnelIP, port, processedTarget)

		case "remove":
			logger.Info("Removing target with port %d", port)

			if n.config.UpdownScript != "" {
				_, err := n.executeUpdownScript(action, proto, target)
				if err != nil {
					logger.Warn("Updown script error: %v", err)
				}
			}

			err = pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				logger.Error("Failed to remove target: %v", err)
				return err
			}
		default:
			logger.Info("Unknown action: %s", action)
		}
	}

	return nil
}

func (n *Newt) executeUpdownScript(action, proto, target string) (string, error) {
	if n.config.UpdownScript == "" {
		return target, nil
	}

	parts := strings.Fields(n.config.UpdownScript)
	if len(parts) == 0 {
		return target, fmt.Errorf("invalid updown script command")
	}

	var cmd *exec.Cmd
	if len(parts) == 1 {
		logger.Info("Executing updown script: %s %s %s %s", n.config.UpdownScript, action, proto, target)
		cmd = exec.Command(parts[0], action, proto, target)
	} else {
		args := append(parts[1:], action, proto, target)
		logger.Info("Executing updown script: %s %s %s %s %s", parts[0], strings.Join(parts[1:], " "), action, proto, target)
		cmd = exec.Command(parts[0], args...)
	}

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("updown script execution failed (exit code %d): %s",
				exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return "", fmt.Errorf("updown script execution failed: %v", err)
	}

	newTarget := strings.TrimSpace(string(output))
	if newTarget != "" {
		logger.Info("Updown script returned new target: %s", newTarget)
		return newTarget, nil
	}

	return target, nil
}
