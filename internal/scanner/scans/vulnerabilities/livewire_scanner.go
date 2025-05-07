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

// LivewireScanner checks for security issues in Laravel Livewire implementations
type LivewireScanner struct{}

// NewLivewireScanner creates a new LivewireScanner
func NewLivewireScanner() *LivewireScanner {
	return &LivewireScanner{}
}

// Name returns the name of the scan
func (s *LivewireScanner) Name() string {
	return "Laravel Livewire Security Scanner"
}

// Description returns the description of the scan
func (s *LivewireScanner) Description() string {
	return "Checks for security issues in Laravel Livewire components"
}

// Category returns the category of the scan
func (s *LivewireScanner) Category() string {
	return "vulnerabilities"
}

// Not needed anymore, using common.BuildURLPath

// Run executes the scan
func (s *LivewireScanner) Run(target string) []common.ScanResult {
	results := []common.ScanResult{}

	// Create HTTP client with appropriate settings
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Check for Livewire specific endpoints
	livewireRoutes := []string{
		"/livewire/livewire.js",
		"/livewire/message/",
		"/livewire",
		"/",  // Check main page for Livewire signatures
	}

	for _, route := range livewireRoutes {
		url := common.BuildURLPath(target, route)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 404 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			
			bodyStr := string(body)
			
			// Check for Livewire signatures
			if strings.Contains(bodyStr, "livewire") || 
			   strings.Contains(bodyStr, "wire:") || 
			   strings.Contains(bodyStr, "Livewire.") {
				
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        route,
					Description: "Laravel Livewire detected",
					Detail:      fmt.Sprintf("The route %s indicates the application is using Laravel Livewire", route),
					StatusCode:  resp.StatusCode,
					Severity:    "info",
				})
				
				// Check for Livewire version
				versionRegex := regexp.MustCompile(`Livewire\.version\s*=\s*['"]([0-9\.]+)['"]`)
				matches := versionRegex.FindStringSubmatch(bodyStr)
				if len(matches) > 1 {
					version := matches[1]
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: fmt.Sprintf("Laravel Livewire version %s detected", version),
						Detail:      "The Livewire version may have known security vulnerabilities",
						StatusCode:  resp.StatusCode,
						Severity:    "info",
					})
					
					// Check for vulnerable versions
					// (Example: check for versions before 2.5.0 that had XSS vulnerabilities)
					if version < "2.5.0" {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Vulnerable Livewire version detected",
							Detail:      fmt.Sprintf("Livewire version %s is vulnerable to XSS attacks (versions before 2.5.0)", version),
							StatusCode:  resp.StatusCode,
							Severity:    "high",
						})
					}
				}
				
				// Check for Livewire CSRF protection
				if !strings.Contains(bodyStr, "csrf-token") && (strings.Contains(route, "livewire/message") || route == "/") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Potential missing CSRF protection in Livewire",
						Detail:      "The Livewire implementation may be missing proper CSRF protection",
						StatusCode:  resp.StatusCode,
						Severity:    "high", 
					})
				}
				
				// Check for insecure component initialization
				if strings.Contains(bodyStr, "window.livewire_app_url") || strings.Contains(bodyStr, "window.livewire_token") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Exposure of Livewire configuration",
						Detail:      "Sensitive Livewire configuration might be exposed in client-side JavaScript",
						StatusCode:  resp.StatusCode,
						Severity:    "medium",
					})
				}
				
				// Check for insecure event listeners
				if strings.Contains(bodyStr, "wire:click") && strings.Contains(bodyStr, "confirm(") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Potential XSS in Livewire event handlers",
						Detail:      "Livewire components with inline JavaScript handlers may be vulnerable to XSS",
						StatusCode:  resp.StatusCode,
						Severity:    "medium",
					})
				}
			}
			
			// Test Livewire message endpoint for weak validation
			if strings.Contains(route, "livewire/message") {
				// Craft a potentially malicious message payload
				testReq, _ := http.NewRequest("POST", url, strings.NewReader(`{"fingerprint":{"id":"test","name":"test","locale":"en","path":"test","method":"GET"},"serverMemo":{},"updates":[{"type":"callMethod","payload":{"id":"alert('XSS')","method":"someMethod","params":[]}}]}`))
				testReq.Header.Set("Content-Type", "application/json")
				testReq.Header.Set("X-Livewire", "true")
				
				testResp, err := client.Do(testReq)
				if err == nil {
					defer testResp.Body.Close()
					
					// If non-error response, might indicate vulnerable validation
					if testResp.StatusCode != 401 && testResp.StatusCode != 403 && testResp.StatusCode != 404 && testResp.StatusCode != 500 {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Potentially vulnerable Livewire message endpoint",
							Detail:      "The Livewire message endpoint might not properly validate component method calls",
							StatusCode:  testResp.StatusCode,
							Severity:    "high",
						})
					}
				}
			}
		}
	}

	return results
}
