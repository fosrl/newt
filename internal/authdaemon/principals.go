package authdaemon

import (
	"encoding/json"
	"fmt"
	"os"
)

// GetPrincipals reads the principals data file at path, looks up the given user, and returns that user's principals as a string slice.
// The file format is JSON: object with username keys and array-of-principals values, e.g. {"alice":["alice","usr-123"],"bob":["bob","usr-456"]}.
// If the user is not found or the file is missing, returns nil and nil.
func GetPrincipals(path, user string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("principals file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read principals file: %w", err)
	}
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse principals file: %w", err)
	}
	return m[user], nil
}
