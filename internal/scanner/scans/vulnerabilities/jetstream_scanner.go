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

// JetstreamScanner checks for security issues in Laravel Jetstream implementation
type JetstreamScanner struct{}

// NewJetstreamScanner creates a new JetstreamScanner
func NewJetstreamScanner() *JetstreamScanner {
	return &JetstreamScanner{}
}

// Name returns the name of the scan
func (s *JetstreamScanner) Name() string {
	return "Laravel Jetstream Security Scanner"
}

// Description returns the description of the scan
func (s *JetstreamScanner) Description() string {
	return "Checks for security issues in Laravel Jetstream scaffolding"
}

// Category returns the category of the scan
func (s *JetstreamScanner) Category() string {
	return "vulnerabilities"
}

// Not needed anymore, using common.BuildURLPath

// Run executes the scan
func (s *JetstreamScanner) Run(target string) []common.ScanResult {
	results := []common.ScanResult{}
	
	// Create HTTP client with appropriate settings
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Check for common Jetstream routes
	jetstreamRoutes := []string{
		"/register",
		"/login",
		"/user/profile",
		"/teams",
		"/api/user",
		"/user/api-tokens",
		"/user/profile-photo",
	}

	for _, route := range jetstreamRoutes {
		url := common.BuildURLPath(target, route)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// If route exists, check for Jetstream
		if resp.StatusCode != 404 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			
			bodyStr := string(body)
			
			// Check for Jetstream signatures in the response
			if strings.Contains(bodyStr, "Jetstream") || 
			   strings.Contains(bodyStr, "Laravel\\Jetstream") ||
			   strings.Contains(bodyStr, "inertia") ||
			   strings.Contains(bodyStr, "livewire") {
				
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        route,
					Description: "Laravel Jetstream detected",
					Detail:      fmt.Sprintf("The route %s indicates the application is using Laravel Jetstream", route),
					StatusCode:  resp.StatusCode,
					Severity:    "info",
				})
				
				// Check for potential API token vulnerabilities if on token page
				if strings.Contains(route, "api-tokens") {
					// Check for lack of CSRF protection
					csrfPattern := regexp.MustCompile(`<meta name="csrf-token".*?>`)
					if !csrfPattern.MatchString(bodyStr) {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Possible missing CSRF protection in Jetstream API tokens page",
							Detail:      "The API tokens page may lack proper CSRF protection, allowing potential token theft",
							StatusCode:  resp.StatusCode,
							Severity:    "high",
						})
					}
				}
				
				// Check for team invitation vulnerabilities
				if strings.Contains(route, "teams") {
					// Check for team enumeration
					if strings.Contains(bodyStr, "Team ID") || strings.Contains(bodyStr, "team-id") {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Possible team enumeration vulnerability in Jetstream Teams",
							Detail:      "The teams functionality may allow enumeration of team IDs, potentially exposing organization structure",
							StatusCode:  resp.StatusCode,
							Severity:    "medium",
						})
					}
				}
				
				// Check for insecure Livewire configuration if using Livewire stack
				if strings.Contains(bodyStr, "livewire:load") || strings.Contains(bodyStr, "wire:") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Jetstream using Livewire stack detected",
						Detail:      "The application is using Jetstream with Livewire stack. Consider running dedicated Livewire security scans",
						StatusCode:  resp.StatusCode,
						Severity:    "info",
					})
				}
				
				// Check for Inertia JS usage which might have different security concerns
				if strings.Contains(bodyStr, "inertia") || strings.Contains(bodyStr, "data-page") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Jetstream using Inertia stack detected",
						Detail:      "The application is using Jetstream with Inertia.js stack. Consider running dedicated Inertia security scans",
						StatusCode:  resp.StatusCode,
						Severity:    "info",
					})
				}
			}
		}
	}

	return results
}
