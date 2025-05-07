package recon

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// RouteDiscoveryScan is a struct that tries to discover Laravel routes
type RouteDiscoveryScan struct {
	client *httpclient.Client
}

// NewRouteDiscoveryScan initializes and returns a new RouteDiscoveryScan instance
func NewRouteDiscoveryScan() *RouteDiscoveryScan {
	return &RouteDiscoveryScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Name returns the name of the scan
func (s *RouteDiscoveryScan) Name() string {
	return "Laravel Route Discovery"
}

// Run executes the scan to discover Laravel routes
func (s *RouteDiscoveryScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common Laravel route paths to check
	routePaths := []string{
		"/login",
		"/register",
		"/password/reset",
		"/password/email",
		"/home",
		"/dashboard",
		"/admin",
		"/api/documentation",
		"/api/user",
		"/api/v1",
		"/sanctum/csrf-cookie",
		"/logout",
		"/profile",
		"/telescope",
		"/horizon",
		"/nova",
		"/livewire",
		"/storage",
		"/logs",
		"/installer",
	}

	// Check for route:list command output leak
	routeListPaths := []string{
		"/routes.txt",
		"/routes.json",
		"/routes.html",
		"/route-list.txt",
		"/storage/routes.txt",
		"/public/routes.txt",
		"/app/routes.txt",
	}

	// Setup custom transport with TLS skip verification
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	customClient := &http.Client{
		Transport: customTransport,
		Timeout:   10 * time.Second,
	}

	// Define headers
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
	}

	// Check common Laravel routes
	for _, path := range routePaths {
		routeURL := common.BuildURLPath(target, path)
		resp, err := s.client.Get(routeURL, headers)
		
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 404 {
			// Read response body
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			bodyContent := string(bodyBytes)
			
			// Check for Laravel-specific content
			isLaravel := false
			if strings.Contains(bodyContent, "Laravel") || 
			   strings.Contains(bodyContent, "csrf-token") || 
			   strings.Contains(bodyContent, "livewire") {
				isLaravel = true
			}
			
			for _, cookie := range resp.Cookies() {
				if strings.Contains(strings.ToLower(cookie.Name), "laravel") || 
				   strings.Contains(strings.ToLower(cookie.Name), "xsrf") {
					isLaravel = true
					break
				}
			}
			
			if isLaravel {
				detail := fmt.Sprintf("Found active Laravel route: %s (Status: %d)", path, resp.StatusCode)
				
				// Check if it's an authentication route
				if strings.Contains(path, "login") || strings.Contains(path, "register") || strings.Contains(path, "password") {
					detail += " - Authentication route"
				}
				
				// Check if it's an admin route
				if strings.Contains(path, "admin") || strings.Contains(path, "dashboard") {
					detail += " - Administrative route"
				}
				
				// Check if it's an API route
				if strings.Contains(path, "api") {
					detail += " - API route"
				}
				
				// Check if it's a development/debug tool
				if strings.Contains(path, "telescope") || strings.Contains(path, "horizon") || strings.Contains(path, "nova") {
					detail += " - Development/debugging tool"
				}
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel route discovered",
					Path:        path,
					StatusCode:  resp.StatusCode,
					Detail:      detail,
					Severity:    determineSeverity(path),
				})
			}
		}
	}
	
	// Check for route:list command output leaks
	for _, path := range routeListPaths {
		routeURL := common.BuildURLPath(target, path)
		resp, err := customClient.Get(routeURL)
		
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			// Read response body
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			bodyContent := string(bodyBytes)
			
			// Check if it looks like route:list output
			if (strings.Contains(bodyContent, "GET") && strings.Contains(bodyContent, "POST")) || 
			   (strings.Contains(bodyContent, "Route") && strings.Contains(bodyContent, "Controller")) ||
			   regexp.MustCompile(`\|\s*GET\s*\|`).MatchString(bodyContent) {
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel route:list command output leaked",
					Path:        path,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("Found leaked route information at %s. This can expose application structure.", path),
					Severity:    "high",
				})
			}
		}
	}

	return results
}

// determineSeverity determines the severity of a found route
func determineSeverity(path string) string {
	// Admin routes are high severity
	if strings.Contains(path, "admin") || 
	   strings.Contains(path, "dashboard") || 
	   strings.Contains(path, "telescope") || 
	   strings.Contains(path, "horizon") || 
	   strings.Contains(path, "nova") || 
	   strings.Contains(path, "logs") {
		return "high"
	}
	
	// API routes are medium severity
	if strings.Contains(path, "api") {
		return "medium"
	}
	
	// Auth routes are low severity
	if strings.Contains(path, "login") || 
	   strings.Contains(path, "register") || 
	   strings.Contains(path, "password") {
		return "low"
	}
	
	// Default severity
	return "info"
}
