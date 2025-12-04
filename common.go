package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"math/rand"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/yaml.v3"
)

const msgHealthFileWriteFailed = "Failed to write health file: %v"

func ping(tnet *netstack.Net, dst string, timeout time.Duration) (time.Duration, error) {
	// logger.Debug("Pinging %s", dst)
	socket, err := tnet.Dial("ping4", dst)
	if err != nil {
		return 0, fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer socket.Close()

	// Set socket buffer sizes to handle high bandwidth scenarios
	if tcpConn, ok := socket.(interface{ SetReadBuffer(int) error }); ok {
		tcpConn.SetReadBuffer(64 * 1024)
	}
	if tcpConn, ok := socket.(interface{ SetWriteBuffer(int) error }); ok {
		tcpConn.SetWriteBuffer(64 * 1024)
	}

	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("newtping"),
	}

	icmpBytes, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	if err := socket.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, fmt.Errorf("failed to set read deadline: %w", err)
	}

	start := time.Now()
	_, err = socket.Write(icmpBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to write ICMP packet: %w", err)
	}

	// Use larger buffer for reading to handle potential network congestion
	readBuffer := make([]byte, 1500)
	n, err := socket.Read(readBuffer)
	if err != nil {
		return 0, fmt.Errorf("failed to read ICMP packet: %w", err)
	}

	replyPacket, err := icmp.ParseMessage(1, readBuffer[:n])
	if err != nil {
		return 0, fmt.Errorf("failed to parse ICMP packet: %w", err)
	}

	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return 0, fmt.Errorf("invalid reply type: got %T, want *icmp.Echo", replyPacket.Body)
	}

	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		return 0, fmt.Errorf("invalid ping reply: got seq=%d data=%q, want seq=%d data=%q",
			replyPing.Seq, replyPing.Data, requestPing.Seq, requestPing.Data)
	}

	latency := time.Since(start)

	// logger.Debug("Ping to %s successful, latency: %v", dst, latency)

	return latency, nil
}

// reliablePing performs multiple ping attempts with adaptive timeout
func reliablePing(tnet *netstack.Net, dst string, baseTimeout time.Duration, maxAttempts int) (time.Duration, error) {
	var lastErr error
	var totalLatency time.Duration
	successCount := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Adaptive timeout: increase timeout for later attempts
		timeout := baseTimeout + time.Duration(attempt-1)*500*time.Millisecond

		// Add jitter to prevent thundering herd
		jitter := time.Duration(rand.Intn(100)) * time.Millisecond
		timeout += jitter

		latency, err := ping(tnet, dst, timeout)
		if err != nil {
			lastErr = err
			logger.Debug("Ping attempt %d/%d failed: %v", attempt, maxAttempts, err)

			// Brief pause between attempts with exponential backoff
			if attempt < maxAttempts {
				backoff := time.Duration(attempt) * 50 * time.Millisecond
				time.Sleep(backoff)
			}
			continue
		}

		totalLatency += latency
		successCount++

		// If we get at least one success, we can return early for health checks
		if successCount > 0 {
			avgLatency := totalLatency / time.Duration(successCount)
			// logger.Debug("Reliable ping succeeded after %d attempts, avg latency: %v", attempt, avgLatency)
			return avgLatency, nil
		}
	}

	if successCount == 0 {
		return 0, fmt.Errorf("all %d ping attempts failed, last error: %v", maxAttempts, lastErr)
	}

	return totalLatency / time.Duration(successCount), nil
}

func pingWithRetry(tnet *netstack.Net, dst string, timeout time.Duration) (stopChan chan struct{}, err error) {

	if healthFile != "" {
		err = os.Remove(healthFile)
		if err != nil {
			logger.Error("Failed to remove health file: %v", err)
		}
	}

	const (
		initialMaxAttempts = 5
		initialRetryDelay  = 2 * time.Second
		maxRetryDelay      = 60 * time.Second // Cap the maximum delay
	)

	stopChan = make(chan struct{})
	attempt := 1
	retryDelay := initialRetryDelay

	// First try with the initial parameters
	logger.Debug("Ping attempt %d", attempt)
	if latency, err := ping(tnet, dst, timeout); err == nil {
		// Successful ping
		logger.Debug("Ping latency: %v", latency)
		logger.Info("Tunnel connection to server established successfully!")
		if healthFile != "" {
			err := os.WriteFile(healthFile, []byte("ok"), 0644)
			if err != nil {
				logger.Warn(msgHealthFileWriteFailed, err)
			}
		}
		return stopChan, nil
	} else {
		logger.Warn("Ping attempt %d failed: %v", attempt, err)
	}

	// Start a goroutine that will attempt pings indefinitely with increasing delays
	go func() {
		attempt = 2 // Continue from attempt 2

		for {
			select {
			case <-stopChan:
				return
			default:
				logger.Debug("Ping attempt %d", attempt)

				if latency, err := ping(tnet, dst, timeout); err != nil {
					logger.Warn("Ping attempt %d failed: %v", attempt, err)

					// Increase delay after certain thresholds but cap it
					if attempt%5 == 0 && retryDelay < maxRetryDelay {
						retryDelay = time.Duration(float64(retryDelay) * 1.5)
						if retryDelay > maxRetryDelay {
							retryDelay = maxRetryDelay
						}
						logger.Info("Increasing ping retry delay to %v", retryDelay)
					}

					time.Sleep(retryDelay)
					attempt++
				} else {
					// Successful ping
					logger.Debug("Ping succeeded after %d attempts", attempt)
					logger.Debug("Ping latency: %v", latency)
					logger.Info("Tunnel connection to server established successfully!")
					if healthFile != "" {
						err := os.WriteFile(healthFile, []byte("ok"), 0644)
						if err != nil {
							logger.Warn(msgHealthFileWriteFailed, err)
						}
					}
				}
			case <-pingStopChan:
				// Stop the goroutine when signaled
				return
			}
		}
	}()

	// Return an error for the first batch of attempts (to maintain compatibility with existing code)
	return stopChan, fmt.Errorf("initial ping attempts failed, continuing in background")
}

func startPingCheck(tnet *netstack.Net, serverIP string, client *websocket.Client, tunnelID string) chan struct{} {
	maxInterval := 6 * time.Second
	currentInterval := pingInterval
	consecutiveFailures := 0
	connectionLost := false

	// Track recent latencies for adaptive timeout calculation
	recentLatencies := make([]time.Duration, 0, 10)

	pingStopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(currentInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Calculate adaptive timeout based on recent latencies
				adaptiveTimeout := pingTimeout
				if len(recentLatencies) > 0 {
					var sum time.Duration
					for _, lat := range recentLatencies {
						sum += lat
					}
					avgLatency := sum / time.Duration(len(recentLatencies))
					// Use 3x average latency as timeout, with minimum of pingTimeout
					adaptiveTimeout = avgLatency * 3
					if adaptiveTimeout < pingTimeout {
						adaptiveTimeout = pingTimeout
					}
					if adaptiveTimeout > 15*time.Second {
						adaptiveTimeout = 15 * time.Second
					}
				}

				// Use reliable ping with multiple attempts
				maxAttempts := 2
				if consecutiveFailures > 4 {
					maxAttempts = 4 // More attempts when connection is unstable
				}

				latency, err := reliablePing(tnet, serverIP, adaptiveTimeout, maxAttempts)
				if err != nil {
					consecutiveFailures++

					// Track recent latencies (add a high value for failures)
					recentLatencies = append(recentLatencies, adaptiveTimeout)
					if len(recentLatencies) > 10 {
						recentLatencies = recentLatencies[1:]
					}

					if consecutiveFailures < 2 {
						logger.Debug("Periodic ping failed (%d consecutive failures): %v", consecutiveFailures, err)
					} else {
						logger.Warn("Periodic ping failed (%d consecutive failures): %v", consecutiveFailures, err)
					}

					// More lenient threshold for declaring connection lost under load
					failureThreshold := 4
					if consecutiveFailures >= failureThreshold && currentInterval < maxInterval {
						if !connectionLost {
							connectionLost = true
							logger.Warn("Connection to server lost after %d failures. Continuous reconnection attempts will be made.", consecutiveFailures)
							if tunnelID != "" {
								telemetry.IncReconnect(context.Background(), tunnelID, "client", telemetry.ReasonTimeout)
							}
							stopFunc = client.SendMessageInterval("newt/ping/request", map[string]interface{}{}, 3*time.Second)
							// Send registration message to the server for backward compatibility
							err := client.SendMessage("newt/wg/register", map[string]interface{}{
								"publicKey":           publicKey.String(),
								"backwardsCompatible": true,
							})
							if err != nil {
								logger.Error("Failed to send registration message: %v", err)
							}
							if healthFile != "" {
								err = os.Remove(healthFile)
								if err != nil {
									logger.Error("Failed to remove health file: %v", err)
								}
							}
						}
						currentInterval = time.Duration(float64(currentInterval) * 1.3) // Slower increase
						if currentInterval > maxInterval {
							currentInterval = maxInterval
						}
						ticker.Reset(currentInterval)
						logger.Debug("Increased ping check interval to %v due to consecutive failures", currentInterval)
					}
				} else {
					// Track recent latencies
					recentLatencies = append(recentLatencies, latency)
					// Record tunnel latency (limit sampling to this periodic check)
					if tunnelID != "" {
						telemetry.ObserveTunnelLatency(context.Background(), tunnelID, "wireguard", latency.Seconds())
					}
					if len(recentLatencies) > 10 {
						recentLatencies = recentLatencies[1:]
					}

					if connectionLost {
						connectionLost = false
						logger.Info("Connection to server restored after %d failures!", consecutiveFailures)
						if healthFile != "" {
							err := os.WriteFile(healthFile, []byte("ok"), 0644)
							if err != nil {
								logger.Warn("Failed to write health file: %v", err)
							}
						}
					}
					if currentInterval > pingInterval {
						currentInterval = time.Duration(float64(currentInterval) * 0.9) // Slower decrease
						if currentInterval < pingInterval {
							currentInterval = pingInterval
						}
						ticker.Reset(currentInterval)
						logger.Debug("Decreased ping check interval to %v after successful ping", currentInterval)
					}
					consecutiveFailures = 0
				}
			case <-pingStopChan:
				logger.Info("Stopping ping check")
				return
			}
		}
	}()

	return pingStopChan
}

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

func updateTargets(pm *proxy.ProxyManager, action string, tunnelIP string, proto string, targetData TargetData) error {
	for _, t := range targetData.Targets {
		// Split the first number off of the target with : separator and use as the port
		parts := strings.Split(t, ":")
		if len(parts) != 3 {
			logger.Info("Invalid target format: %s", t)
			continue
		}

		// Get the port as an int
		port := 0
		_, err := fmt.Sscanf(parts[0], "%d", &port)
		if err != nil {
			logger.Info("Invalid port: %s", parts[0])
			continue
		}

		switch action {
		case "add":
			target := parts[1] + ":" + parts[2]

			// Call updown script if provided
			processedTarget := target
			if updownScript != "" {
				newTarget, err := executeUpdownScript(action, proto, target)
				if err != nil {
					logger.Warn("Updown script error: %v", err)
				} else if newTarget != "" {
					processedTarget = newTarget
				}
			}

			// Only remove the specific target if it exists
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				// Ignore "target not found" errors as this is expected for new targets
				if !strings.Contains(err.Error(), "target not found") {
					logger.Error("Failed to remove existing target: %v", err)
				}
			}

			// Add the new target
			pm.AddTarget(proto, tunnelIP, port, processedTarget)

		case "remove":
			logger.Info("Removing target with port %d", port)

			target := parts[1] + ":" + parts[2]

			// Call updown script if provided
			if updownScript != "" {
				_, err := executeUpdownScript(action, proto, target)
				if err != nil {
					logger.Warn("Updown script error: %v", err)
				}
			}

			err := pm.RemoveTarget(proto, tunnelIP, port)
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

func executeUpdownScript(action, proto, target string) (string, error) {
	if updownScript == "" {
		return target, nil
	}

	// Split the updownScript in case it contains spaces (like "/usr/bin/python3 script.py")
	parts := strings.Fields(updownScript)
	if len(parts) == 0 {
		return target, fmt.Errorf("invalid updown script command")
	}

	var cmd *exec.Cmd
	if len(parts) == 1 {
		// If it's a single executable
		logger.Info("Executing updown script: %s %s %s %s", updownScript, action, proto, target)
		cmd = exec.Command(parts[0], action, proto, target)
	} else {
		// If it includes interpreter and script
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

	// If the script returns a new target, use it
	newTarget := strings.TrimSpace(string(output))
	if newTarget != "" {
		logger.Info("Updown script returned new target: %s", newTarget)
		return newTarget, nil
	}

	return target, nil
}

func sendBlueprint(client *websocket.Client) error {
	if blueprintFile == "" {
		return nil
	}
	// try to read the blueprint file
	blueprintData, err := os.ReadFile(blueprintFile)
	if err != nil {
		logger.Error("Failed to read blueprint file: %v", err)
	} else {
		// first we should convert the yaml to json and error if the yaml is bad
		var yamlObj interface{}
		var blueprintJsonData string

		err = yaml.Unmarshal(blueprintData, &yamlObj)
		if err != nil {
			logger.Error("Failed to parse blueprint YAML: %v", err)
		} else {
			// convert to json
			jsonBytes, err := json.Marshal(yamlObj)
			if err != nil {
				logger.Error("Failed to convert blueprint to JSON: %v", err)
			} else {
				blueprintJsonData = string(jsonBytes)
				logger.Debug("Converted blueprint to JSON: %s", blueprintJsonData)
			}
		}

		// if we have valid json data, we can send it to the server
		if blueprintJsonData == "" {
			logger.Error("No valid blueprint JSON data to send to server")
			return nil
		}

		logger.Info("Sending blueprint to server for application")

		// send the blueprint data to the server
		err = client.SendMessage("newt/blueprint/apply", map[string]interface{}{
			"blueprint": blueprintJsonData,
		})
	}

	return nil
}
