package newt

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type pingFunc func(dst string, timeout time.Duration) (time.Duration, error)

const msgHealthFileWriteFailed = "Failed to write health file: %v"

func pingNative(dst string, timeout time.Duration) (time.Duration, error) {
	timeoutSecs := int(timeout.Seconds())
	if timeoutSecs < 1 {
		timeoutSecs = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), dst)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Milliseconds())), dst)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSecs), dst)
	}

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("native ping to %s failed: %w", dst, err)
	}
	return time.Since(start), nil
}

func ping(tnet *netstack.Net, dst string, timeout time.Duration) (time.Duration, error) {
	socket, err := tnet.Dial("ping4", dst)
	if err != nil {
		return 0, fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer socket.Close()

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

	return time.Since(start), nil
}

func reliablePing(fn pingFunc, dst string, baseTimeout time.Duration, maxAttempts int) (time.Duration, error) {
	var lastErr error
	var totalLatency time.Duration
	successCount := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		timeout := baseTimeout + time.Duration(attempt-1)*500*time.Millisecond
		jitter := time.Duration(rand.Intn(100)) * time.Millisecond
		timeout += jitter

		latency, err := fn(dst, timeout)
		if err != nil {
			lastErr = err
			logger.Debug("Ping attempt %d/%d failed: %v", attempt, maxAttempts, err)

			if attempt < maxAttempts {
				backoff := time.Duration(attempt) * 50 * time.Millisecond
				time.Sleep(backoff)
			}
			continue
		}

		totalLatency += latency
		successCount++
		return totalLatency / time.Duration(successCount), nil
	}

	return 0, fmt.Errorf("all %d ping attempts failed, last error: %v", maxAttempts, lastErr)
}

// shouldFireRecovery decides whether the data-plane recovery flow should run on
// this tick. See startPingCheck for the rationale behind separating recovery
// from the backoff ramp.
func shouldFireRecovery(consecutiveFailures, failureThreshold int, connectionLost bool) bool {
	return consecutiveFailures >= failureThreshold && !connectionLost
}

func (n *Newt) pingWithRetry(fn pingFunc, dst string, timeout time.Duration) (stopChan chan struct{}, err error) {
	if n.config.HealthFile != "" {
		err = os.Remove(n.config.HealthFile)
		if err != nil {
			logger.Error("Failed to remove health file: %v", err)
		}
	}

	const (
		initialRetryDelay = 2 * time.Second
		maxRetryDelay     = 60 * time.Second
	)

	stopChan = make(chan struct{})
	attempt := 1
	retryDelay := initialRetryDelay

	logger.Debug("Ping attempt %d", attempt)
	if latency, err := fn(dst, timeout); err == nil {
		logger.Debug("Ping latency: %v", latency)
		logger.Info("Tunnel connection to server established successfully!")
		if n.config.HealthFile != "" {
			if err := os.WriteFile(n.config.HealthFile, []byte("ok"), 0644); err != nil {
				logger.Warn(msgHealthFileWriteFailed, err)
			}
		}
		return stopChan, nil
	} else {
		logger.Warn("Ping attempt %d failed: %v", attempt, err)
	}

	go func() {
		attempt = 2

		for {
			select {
			case <-stopChan:
				return
			default:
				logger.Debug("Ping attempt %d", attempt)

				if latency, err := fn(dst, timeout); err != nil {
					logger.Warn("Ping attempt %d failed: %v", attempt, err)

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
					logger.Debug("Ping succeeded after %d attempts", attempt)
					logger.Debug("Ping latency: %v", latency)
					logger.Info("Tunnel connection to server established successfully!")
					if n.config.HealthFile != "" {
						if err := os.WriteFile(n.config.HealthFile, []byte("ok"), 0644); err != nil {
							logger.Warn(msgHealthFileWriteFailed, err)
						}
					}
					return
				}
			case <-n.pingStopChan:
				return
			}
		}
	}()

	return stopChan, fmt.Errorf("initial ping attempts failed, continuing in background")
}

func (n *Newt) startPingCheck(fn pingFunc, serverIP, tunnelID string) chan struct{} {
	maxInterval := 6 * time.Second
	currentInterval := n.config.PingInterval
	consecutiveFailures := 0
	connectionLost := false

	recentLatencies := make([]time.Duration, 0, 10)

	pingStopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(currentInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				adaptiveTimeout := n.config.PingTimeout
				if len(recentLatencies) > 0 {
					var sum time.Duration
					for _, lat := range recentLatencies {
						sum += lat
					}
					avgLatency := sum / time.Duration(len(recentLatencies))
					adaptiveTimeout = avgLatency * 3
					if adaptiveTimeout < n.config.PingTimeout {
						adaptiveTimeout = n.config.PingTimeout
					}
					if adaptiveTimeout > 15*time.Second {
						adaptiveTimeout = 15 * time.Second
					}
				}

				maxAttempts := 2
				if consecutiveFailures > 4 {
					maxAttempts = 4
				}

				latency, err := reliablePing(fn, serverIP, adaptiveTimeout, maxAttempts)
				if err != nil {
					consecutiveFailures++

					recentLatencies = append(recentLatencies, adaptiveTimeout)
					if len(recentLatencies) > 10 {
						recentLatencies = recentLatencies[1:]
					}

					if consecutiveFailures < 2 {
						logger.Debug("Periodic ping failed (%d consecutive failures): %v", consecutiveFailures, err)
					} else {
						logger.Warn("Periodic ping failed (%d consecutive failures): %v", consecutiveFailures, err)
					}

					failureThreshold := 4
					if shouldFireRecovery(consecutiveFailures, failureThreshold, connectionLost) {
						connectionLost = true
						logger.Warn("Connection to server lost after %d failures. Continuous reconnection attempts will be made.", consecutiveFailures)
						if tunnelID != "" {
							telemetry.IncReconnect(context.Background(), tunnelID, "client", telemetry.ReasonTimeout)
						}
						pingChainId := generateChainId()
						n.pendingPingChainId = pingChainId
						n.stopFunc = n.client.SendMessageInterval("newt/ping/request", map[string]interface{}{
							"chainId": pingChainId,
						}, 3*time.Second)
						bcChainId := generateChainId()
						n.pendingRegisterChainId = bcChainId
						if err := n.client.SendMessage("newt/wg/register", map[string]interface{}{
							"publicKey":           n.publicKey.String(),
							"backwardsCompatible": true,
							"chainId":             bcChainId,
						}); err != nil {
							logger.Error("Failed to send registration message: %v", err)
						}
						if n.config.HealthFile != "" {
							if err := os.Remove(n.config.HealthFile); err != nil {
								logger.Error("Failed to remove health file: %v", err)
							}
						}
					}
					if consecutiveFailures >= failureThreshold && currentInterval < maxInterval {
						currentInterval = time.Duration(float64(currentInterval) * 1.3)
						if currentInterval > maxInterval {
							currentInterval = maxInterval
						}
					}
				} else {
					recentLatencies = append(recentLatencies, latency)
					if tunnelID != "" {
						telemetry.ObserveTunnelLatency(context.Background(), tunnelID, "wireguard", latency.Seconds())
					}
					if len(recentLatencies) > 10 {
						recentLatencies = recentLatencies[1:]
					}

					if connectionLost {
						connectionLost = false
						logger.Info("Connection to server restored after %d failures!", consecutiveFailures)
						if n.config.HealthFile != "" {
							if err := os.WriteFile(n.config.HealthFile, []byte("ok"), 0644); err != nil {
								logger.Warn("Failed to write health file: %v", err)
							}
						}
					}
					if currentInterval > n.config.PingInterval {
						currentInterval = time.Duration(float64(currentInterval) * 0.9)
						if currentInterval < n.config.PingInterval {
							currentInterval = n.config.PingInterval
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
