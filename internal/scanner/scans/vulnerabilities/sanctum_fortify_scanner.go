package vulnerabilities

import (
	"crypto/tls"
	"fmt"
	"laravelmap/internal/common"
	"net/http"
	"strings"
	"time"
)

// SanctumFortifyScanner checks for security issues in Laravel Sanctum and Fortify implementations
type SanctumFortifyScanner struct{}

// NewSanctumFortifyScanner creates a new SanctumFortifyScanner
func NewSanctumFortifyScanner() *SanctumFortifyScanner {
	return &SanctumFortifyScanner{}
}

// Name returns the name of the scan
func (s *SanctumFortifyScanner) Name() string {
	return "Laravel Sanctum/Fortify Security Scanner"
}

// Description returns the description of the scan
func (s *SanctumFortifyScanner) Description() string {
	return "Checks for security issues in Laravel Sanctum and Fortify authentication systems"
}

// Category returns the category of the scan
func (s *SanctumFortifyScanner) Category() string {
	return "vulnerabilities"
}

// Not needed anymore, using common.BuildURLPath

// Run executes the scan
func (s *SanctumFortifyScanner) Run(target string) []common.ScanResult {
	results := []common.ScanResult{}

	// Create HTTP client with appropriate settings
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Check for Sanctum token routes and possible vulnerabilities
	tokenRoutes := []string{
		"/sanctum/csrf-cookie",
		"/api/sanctum/token",
		"/api/tokens",
		"/api/auth/tokens",
	}

	for _, route := range tokenRoutes {
		url := common.BuildURLPath(target, route)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 404 {
			// Found potentially active Sanctum route
			results = append(results, common.ScanResult{
				Category:    s.Category(),
				ScanName:    s.Name(),
				Path:        route,
				Description: "Found potential Laravel Sanctum API token endpoint",
				Detail:      fmt.Sprintf("The route %s returned status code %d which may indicate a Sanctum token endpoint", route, resp.StatusCode),
				StatusCode:  resp.StatusCode,
				Severity:    "low",
			})

			// Check for insecure headers
			if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        route,
					Description: "Insecure CORS configuration in Laravel Sanctum endpoint",
					Detail:      "The Access-Control-Allow-Origin header is set to * which allows any origin to access the API tokens",
					StatusCode:  resp.StatusCode,
					Severity:    "high",
				})
			}
		}
	}

	// Check for Fortify endpoints
	fortifyRoutes := []string{
		"/forgot-password",
		"/reset-password",
		"/user/confirm-password",
		"/user/confirmed-password-status",
		"/user/confirmed-two-factor-authentication",
		"/user/two-factor-authentication",
		"/two-factor-challenge",
	}

	for _, route := range fortifyRoutes {
		url := common.BuildURLPath(target, route)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 404 {
			// Test rate limiting on password reset
			if strings.Contains(route, "forgot-password") || strings.Contains(route, "reset-password") {
				// Try multiple requests to test rate limiting
				for i := 0; i < 10; i++ {
					resp, err := client.Get(url)
					if err != nil {
						break
					}
					resp.Body.Close()
					
					// If we don't get rate limited after 10 requests, it might be a vulnerability
					if i == 9 && resp.StatusCode != 429 {
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        route,
							Description: "Fortify password reset endpoint lacks rate limiting",
							Detail:      "The password reset functionality does not implement proper rate limiting, which could lead to brute force attacks",
							StatusCode:  resp.StatusCode,
							Severity:    "high",
						})
					}
				}
			}
		}
	}

	return results
}
