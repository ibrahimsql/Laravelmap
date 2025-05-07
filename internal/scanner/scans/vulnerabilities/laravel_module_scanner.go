package vulnerabilities

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"net/http"
	"strings"
	"time"
)

// LaravelModuleScanner checks for security issues in various Laravel modules and components
type LaravelModuleScanner struct{}

// NewLaravelModuleScanner creates a new LaravelModuleScanner
func NewLaravelModuleScanner() *LaravelModuleScanner {
	return &LaravelModuleScanner{}
}

// Name returns the name of the scan
func (s *LaravelModuleScanner) Name() string {
	return "Laravel Module Security Scanner"
}

// Description returns the description of the scan
func (s *LaravelModuleScanner) Description() string {
	return "Checks for security issues in Laravel specific modules and components"
}

// Category returns the category of the scan
func (s *LaravelModuleScanner) Category() string {
	return "vulnerabilities"
}

// targetURL combines the target URL and path
func targetURL(baseURL, path string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	path = strings.TrimPrefix(path, "/")
	return fmt.Sprintf("%s/%s", baseURL, path)
}

// Run executes the scan
func (s *LaravelModuleScanner) Run(target string) []common.ScanResult {
	results := []common.ScanResult{}

	// Create HTTP client with appropriate settings
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Add checks for Laravel Sanctum/Fortify
	routes := map[string]string{
		// Sanctum/Fortify routes
		"/sanctum/csrf-cookie":            "Laravel Sanctum CSRF cookie endpoint",
		"/api/sanctum/token":              "Laravel Sanctum token endpoint",
		"/forgot-password":                "Laravel Fortify password reset",
		"/reset-password":                 "Laravel Fortify password reset",
		"/user/confirm-password":          "Laravel Fortify password confirmation",
		"/user/two-factor-authentication": "Laravel Fortify 2FA endpoint",
		"/two-factor-challenge":           "Laravel Fortify 2FA challenge",
		
		// Jetstream routes
		"/register":           "Laravel Jetstream registration",
		"/login":              "Laravel Jetstream login",
		"/user/profile":       "Laravel Jetstream profile",
		"/teams":              "Laravel Jetstream teams",
		"/api/user":           "Laravel Jetstream API",
		"/user/api-tokens":    "Laravel Jetstream API tokens",
		"/user/profile-photo": "Laravel Jetstream profile photo",
		
		// Echo/Broadcasting routes
		"/broadcasting/auth":  "Laravel Echo broadcasting auth",
		"/socket.io":          "Laravel Echo/Socket.io endpoint",
		"/laravel-websockets": "Laravel WebSockets server",
		"/js/echo.js":         "Laravel Echo client script",
		
		// Livewire routes
		"/livewire/livewire.js": "Laravel Livewire script",
		"/livewire/message":     "Laravel Livewire message endpoint",
		"/livewire":             "Laravel Livewire endpoint",
	}

	// Check all routes
	for route, description := range routes {
		url := targetURL(target, route)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		
		// If route exists, add it to results
		if resp.StatusCode != 404 {
			body, _ := ioutil.ReadAll(resp.Body)
			bodyStr := string(body)
			resp.Body.Close()
			
			// Determine module type
			moduleType := "Unknown"
			if strings.Contains(route, "sanctum") || strings.Contains(route, "password") || strings.Contains(route, "factor") {
				moduleType = "Sanctum/Fortify"
			} else if strings.Contains(route, "profile") || strings.Contains(route, "teams") || strings.Contains(route, "api-tokens") {
				moduleType = "Jetstream"
			} else if strings.Contains(route, "broadcasting") || strings.Contains(route, "socket") || strings.Contains(route, "echo") {
				moduleType = "Echo/Broadcasting"
			} else if strings.Contains(route, "livewire") {
				moduleType = "Livewire"
			}
			
			// Add basic detection result
			results = append(results, common.ScanResult{
				Category:    s.Category(),
				ScanName:    s.Name(),
				Path:        route,
				Description: fmt.Sprintf("%s module detected: %s", moduleType, description),
				Detail:      fmt.Sprintf("The route %s returned status code %d which indicates a Laravel %s component", route, resp.StatusCode, moduleType),
				StatusCode:  resp.StatusCode,
				Severity:    "info",
			})
			
			// Check for common security issues based on module type
			switch moduleType {
			case "Sanctum/Fortify":
				// Check for CORS misconfiguration
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
				
			case "Jetstream":
				// Check for CSRF protection
				if !strings.Contains(bodyStr, "csrf-token") && strings.Contains(route, "api-tokens") {
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
				
			case "Echo/Broadcasting":
				// Check for encryption configuration
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
				
			case "Livewire":
				// Check for Livewire version
				if strings.Contains(bodyStr, "Livewire.version") && strings.Contains(bodyStr, "2.0") {
					results = append(results, common.ScanResult{
						Category:    s.Category(),
						ScanName:    s.Name(),
						Path:        route,
						Description: "Potentially vulnerable Livewire version",
						Detail:      "An older version of Livewire (2.0.x) may be in use, which could contain security vulnerabilities",
						StatusCode:  resp.StatusCode,
						Severity:    "medium",
					})
				}
			}
		}
	}

	// Check for Eloquent ORM vulnerabilities via common API endpoints
	apiEndpoints := []string{
		"/api/users",
		"/api/posts",
		"/api/products",
		"/users",
		"/posts",
		"/products",
		"/search",
	}
	
	// SQL injection payloads
	testPayloads := []string{
		"1' OR '1'='1",
		"1; SELECT * FROM users--",
	}
	
	// Test each endpoint with SQL injection payloads
	for _, endpoint := range apiEndpoints {
		baseUrl := targetURL(target, endpoint)
		// First check if the endpoint exists
		resp, err := client.Get(baseUrl)
		if err != nil || resp.StatusCode == 404 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		resp.Body.Close()
		
		// If endpoint exists, test with SQL injection payloads
		for _, payload := range testPayloads {
			testUrl := fmt.Sprintf("%s?id=%s", baseUrl, payload)
			payloadResp, err := client.Get(testUrl)
			if err != nil {
				continue
			}
			
			body, _ := ioutil.ReadAll(payloadResp.Body)
			payloadResp.Body.Close()
			bodyStr := string(body)
			
			// Check for SQL error messages
			if strings.Contains(bodyStr, "SQLSTATE") || 
			   strings.Contains(bodyStr, "syntax error") || 
			   strings.Contains(bodyStr, "mysql") {
				results = append(results, common.ScanResult{
					Category:    s.Category(),
					ScanName:    s.Name(),
					Path:        testUrl,
					Description: "Potential SQL Injection in Laravel Eloquent ORM",
					Detail:      fmt.Sprintf("SQL error detected when using payload: id=%s", payload),
					StatusCode:  payloadResp.StatusCode,
					Severity:    "high",
				})
				break
			}
		}
	}

	return results
}
