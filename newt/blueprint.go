package newt

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/websocket"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// interpolateBlueprint replaces {{env.VAR}} tokens with their environment variable values.
func interpolateBlueprint(data []byte) []byte {
	re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	return re.ReplaceAllFunc(data, func(match []byte) []byte {
		inner := strings.TrimSpace(string(match[2 : len(match)-2]))

		if strings.HasPrefix(inner, "env.") {
			varName := strings.TrimPrefix(inner, "env.")
			return []byte(os.Getenv(varName))
		}

		return match
	})
}

func sendBlueprint(client *websocket.Client, file string) error {
	if file == "" {
		return nil
	}
	blueprintData, err := os.ReadFile(file)
	if err != nil {
		logger.Error("Failed to read blueprint file: %v", err)
		return nil
	}

	blueprintData = interpolateBlueprint(blueprintData)

	var yamlObj interface{}
	if err := yaml.Unmarshal(blueprintData, &yamlObj); err != nil {
		logger.Error("Failed to parse blueprint YAML: %v", err)
		return nil
	}

	jsonBytes, err := json.Marshal(yamlObj)
	if err != nil {
		logger.Error("Failed to convert blueprint to JSON: %v", err)
		return nil
	}

	blueprintJsonData := string(jsonBytes)
	logger.Debug("Converted blueprint to JSON: %s", blueprintJsonData)

	if blueprintJsonData == "" {
		logger.Error("No valid blueprint JSON data to send to server")
		return nil
	}

	logger.Info("Sending blueprint to server for application")

	return client.SendMessage("newt/blueprint/apply", map[string]interface{}{
		"blueprint": blueprintJsonData,
	})
}

func watchBlueprintFile(ctx context.Context, filePath string, send func() error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("blueprint watcher: failed to create: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(filePath); err != nil {
		logger.Error("blueprint watcher: failed to watch %s: %v", filePath, err)
		return
	}

	logger.Info("Watching blueprint file for changes: %s", filePath)

	var debounce *time.Timer
	scheduleSend := func() {
		if debounce != nil {
			debounce.Stop()
		}
		debounce = time.AfterFunc(500*time.Millisecond, func() {
			logger.Info("Blueprint file changed, resending...")
			if err := send(); err != nil {
				logger.Error("blueprint watcher: resend failed: %v", err)
			}
		})
	}

	for {
		select {
		case <-ctx.Done():
			if debounce != nil {
				debounce.Stop()
			}
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			switch {
			case event.Has(fsnotify.Write) || event.Has(fsnotify.Create):
				if event.Has(fsnotify.Create) {
					_ = watcher.Add(filePath)
				}
				scheduleSend()
			case event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename):
				_ = watcher.Add(filePath)
				scheduleSend()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Error("blueprint watcher: %v", err)
		}
	}
}
