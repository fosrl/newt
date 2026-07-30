// Package exitnode implements the exit-node ping dance run before
// registering with the server: request the candidate exit nodes, ping each
// one over HTTP, and report the results so the server can pick the best one.
// It is shared between newt and olm, which both register the same way.
package exitnode

import (
	"net/http"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
)

// ExitNodeData is the payload the server sends in response to a
// "*/ping/request" message.
type ExitNodeData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
	ChainId   string     `json:"chainId"`
}

// ExitNode is a candidate exit node offered by the server for ping selection.
type ExitNode struct {
	ID                     int     `json:"exitNodeId"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	Weight                 float64 `json:"weight"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

// ExitNodePingResult is the measured latency (or error) for one exit node,
// sent back to the server in the "*/wg/register" message's pingResults field.
type ExitNodePingResult struct {
	ExitNodeID             int     `json:"exitNodeId"`
	LatencyMs              int64   `json:"latencyMs"`
	Weight                 float64 `json:"weight"`
	Error                  string  `json:"error,omitempty"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

// PingExitNodes pings the given exit nodes over HTTP and returns a per-node
// ExitNodePingResult suitable for inclusion in a wg/register message's
// pingResults field, so the server can select the best exit node.
//
// If there's only one exit node, or preferEndpoint names one of them, the
// matching node is returned immediately with LatencyMs 0 and no pinging is
// done. Otherwise every node is pinged pingAttempts times over HTTP GET
// <endpoint>/ping and the average latency of successful attempts is used.
//
// When alreadyConnected is true, a node flagged WasPreviouslyConnected is
// excluded from the results as long as at least one other healthy node is
// available, biasing reconnects toward switching away from a possibly
// degraded node.
func PingExitNodes(exitNodes []ExitNode, preferEndpoint string, alreadyConnected bool) []ExitNodePingResult {
	if len(exitNodes) == 0 {
		return nil
	}

	if len(exitNodes) == 1 || preferEndpoint != "" {
		selected := exitNodes[0]
		if preferEndpoint != "" {
			for _, node := range exitNodes {
				if node.Endpoint == preferEndpoint {
					selected = node
					break
				}
			}
		}

		logger.Debug("Only one exit node available, using it directly: %s", selected.Endpoint)

		return []ExitNodePingResult{
			{
				ExitNodeID:             selected.ID,
				LatencyMs:              0,
				Weight:                 selected.Weight,
				Error:                  "",
				Name:                   selected.Name,
				Endpoint:               selected.Endpoint,
				WasPreviouslyConnected: selected.WasPreviouslyConnected,
			},
		}
	}

	type nodeResult struct {
		Node    ExitNode
		Latency time.Duration
		Err     error
	}

	results := make([]nodeResult, len(exitNodes))
	const pingAttempts = 3
	for i, node := range exitNodes {
		var totalLatency time.Duration
		var lastErr error
		successes := 0
		httpClient := &http.Client{
			Timeout: 5 * time.Second,
		}
		url := node.Endpoint
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		if !strings.HasSuffix(url, "/ping") {
			url = strings.TrimRight(url, "/") + "/ping"
		}
		for j := 0; j < pingAttempts; j++ {
			start := time.Now()
			resp, err := httpClient.Get(url)
			latency := time.Since(start)
			if err != nil {
				lastErr = err
				logger.Warn("Failed to ping exit node %d (%s) attempt %d: %v", node.ID, url, j+1, err)
				continue
			}
			resp.Body.Close()
			totalLatency += latency
			successes++
		}
		var avgLatency time.Duration
		if successes > 0 {
			avgLatency = totalLatency / time.Duration(successes)
		}
		if successes == 0 {
			results[i] = nodeResult{Node: node, Latency: 0, Err: lastErr}
		} else {
			results[i] = nodeResult{Node: node, Latency: avgLatency, Err: nil}
		}
	}

	var pingResults []ExitNodePingResult
	for _, res := range results {
		errMsg := ""
		if res.Err != nil {
			errMsg = res.Err.Error()
		}
		pingResults = append(pingResults, ExitNodePingResult{
			ExitNodeID:             res.Node.ID,
			LatencyMs:              res.Latency.Milliseconds(),
			Weight:                 res.Node.Weight,
			Error:                  errMsg,
			Name:                   res.Node.Name,
			Endpoint:               res.Node.Endpoint,
			WasPreviouslyConnected: res.Node.WasPreviouslyConnected,
		})
	}

	if alreadyConnected {
		var filteredPingResults []ExitNodePingResult
		previouslyConnectedNodeIdx := -1
		for i, res := range pingResults {
			if res.WasPreviouslyConnected {
				previouslyConnectedNodeIdx = i
			}
		}
		goodNodeCount := 0
		for i, res := range pingResults {
			if i != previouslyConnectedNodeIdx && res.LatencyMs > 0 && res.Error == "" {
				goodNodeCount++
			}
		}
		if previouslyConnectedNodeIdx != -1 && goodNodeCount > 0 {
			for i, res := range pingResults {
				if i != previouslyConnectedNodeIdx {
					filteredPingResults = append(filteredPingResults, res)
				}
			}
			pingResults = filteredPingResults
			logger.Info("Excluding previously connected exit node from ping results due to other available nodes")
		}
	}

	return pingResults
}
