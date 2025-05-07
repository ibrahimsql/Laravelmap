package common

import (
	"fmt"
	"strings"
)

// BuildURLPath combines the target URL and path
func BuildURLPath(baseURL, path string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	path = strings.TrimPrefix(path, "/")
	return fmt.Sprintf("%s/%s", baseURL, path)
}
