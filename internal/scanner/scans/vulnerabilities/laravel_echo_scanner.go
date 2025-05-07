package vulnerabilities

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// LaravelEchoScanner checks for security issues in Laravel Echo implementations
type LaravelEchoScanner struct{}

// NewLaravelEchoScanner creates a new LaravelEchoScanner
func NewLaravelEchoScanner() *LaravelEchoScanner {
	return &LaravelEchoScanner{}
}

// Name returns the name of the scan
func (s *LaravelEchoScanner) Name() string {
	return "Laravel Echo Security Scanner"
}

// Description returns the description of the scan
func (s *LaravelEchoScanner) Description() string {
	return "Checks for security issues in Laravel Echo and broadcasting system"
}

// Category returns the category of the scan
func (s *LaravelEchoScanner) Category() string {
	return "vulnerabilities"
}

// Not needed anymore, using common.BuildURLPath

// Run executes the scan
func (s *LaravelEchoScanner) Run(target string) []common.ScanResult {
	results := []common.ScanResult{}

	// Create HTTP client with appropriate settings
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Check for Laravel Echo related endpoints
	echoRoutes := []string{
		"/broadcasting/auth",
		"/socket.io",
		"/laravel-websockets",
		"/js/app.js",
		"/js/echo.js",
	}

	for _, route := range echoRoutes {
		url := common.BuildURLPath(target, route)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// If found a potential Echo-related endpoint
		if resp.StatusCode != 404 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			
			bodyStr := string(body)
			
			// Check if broadcasting endpoint exists
			if strings.Contains(route, "broadcasting/auth") {
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        route,
					Description: "Laravel Broadcasting authentication endpoint detected",
					Detail:      "The application uses Laravel Echo broadcasting system",
					StatusCode:  resp.StatusCode,
					Severity:    "info",
				})
				
				// Try to test the endpoint without authentication
				unauthReq, _ := http.NewRequest("POST", url, strings.NewReader("channel_name=private-test&socket_id=1234.1234"))
				unauthReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				unauthResp, err := client.Do(unauthReq)
				
				if err == nil {
					defer unauthResp.Body.Close()
					
					// If the server returns anything other than 401/403, it may not be properly validating auth
					if unauthResp.StatusCode != 401 && unauthResp.StatusCode != 403 {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Potentially insecure broadcasting authentication",
							Detail:      fmt.Sprintf("The broadcasting auth endpoint returned %d instead of 401/403 for unauthenticated request", unauthResp.StatusCode),
							StatusCode:  unauthResp.StatusCode,
							Severity:    "high",
						})
					}
				}
			}
			
			// Check for Laravel WebSockets
			if strings.Contains(route, "laravel-websockets") {
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        route,
					Description: "Laravel WebSockets server detected",
					Detail:      "The application uses Laravel WebSockets server for real-time communication",
					StatusCode:  resp.StatusCode,
					Severity:    "info",
				})
				
				// Check if dashboard is exposed without authentication
				if resp.StatusCode == 200 && strings.Contains(bodyStr, "Laravel WebSockets") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Exposed Laravel WebSockets dashboard",
						Detail:      "The Laravel WebSockets dashboard is publicly accessible which may expose sensitive information",
						StatusCode:  resp.StatusCode,
						Severity:    "high",
					})
				}
			}
			
			// Check for Socket.io
			if strings.Contains(route, "socket.io") {
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        route,
					Description: "Socket.io endpoint detected",
					Detail:      "The application uses Socket.io for real-time communication",
					StatusCode:  resp.StatusCode,
					Severity:    "info",
				})
			}
			
			// Check JS files for Echo configuration
			if strings.Contains(route, ".js") {
				// Check for Echo initialization
				echoRegex := regexp.MustCompile(`Echo\s*=\s*new\s*Laravel\.Echo`)
				if echoRegex.MatchString(bodyStr) {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Laravel Echo client configuration detected",
						Detail:      "Found Laravel Echo initialization in JavaScript file",
						StatusCode:  resp.StatusCode,
						Severity:    "info",
					})
					
					// Check for insecure configuration
					if strings.Contains(bodyStr, "encrypted: false") {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Insecure Laravel Echo configuration",
							Detail:      "Laravel Echo is configured with encryption disabled",
							StatusCode:  resp.StatusCode,
							Severity:    "high",
						})
					}
					
					// Check Pusher key exposure
					pusherKeyRegex := regexp.MustCompile(`key:\s*['"]([a-zA-Z0-9]+)['"]`)
					matches := pusherKeyRegex.FindStringSubmatch(bodyStr)
					if len(matches) > 1 {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Exposed Pusher API key",
							Detail:      fmt.Sprintf("Found Pusher API key in client-side code: %s", matches[1]),
							StatusCode:  resp.StatusCode,
							Severity:    "medium",
						})
					}
				}
			}
		}
	}

	return results
}
