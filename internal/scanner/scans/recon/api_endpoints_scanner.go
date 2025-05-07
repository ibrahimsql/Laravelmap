package recon

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// APIEndpointsScan is a struct that discovers API endpoints in Laravel applications
type APIEndpointsScan struct {
	client *httpclient.Client
}

// NewAPIEndpointsScan initializes and returns a new APIEndpointsScan instance
func NewAPIEndpointsScan() *APIEndpointsScan {
	return &APIEndpointsScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Name returns the name of the scan
func (s *APIEndpointsScan) Name() string {
	return "Laravel API Endpoints Scanner"
}

// Run executes the scan to discover Laravel API endpoints
func (s *APIEndpointsScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common Laravel API paths to check
	apiPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/user",
		"/api/users",
		"/api/login",
		"/api/register",
		"/api/auth/login",
		"/api/auth/register",
		"/api/products",
		"/api/posts",
		"/api/articles",
		"/api/items",
		"/api/profile",
		"/api/documentation",
		"/api/docs",
		"/docs/api",
		"/swagger/ui",
		"/api/swagger",
		"/api/graphql",
		"/graphql",
	}

	// API documentation paths that might reveal API structure
	docPaths := []string{
		"/api/documentation",
		"/docs",
		"/swagger",
		"/swagger-ui",
		"/api-docs",
		"/api/docs",
		"/documentation",
		"/openapi",
	}

	// Setup custom transport with TLS skip verification
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	customClient := &http.Client{
		Transport: customTransport,
		Timeout:   10 * time.Second,
	}

	// Define headers for API requests
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		"Accept":          "application/json",
		"Content-Type":    "application/json",
		"X-Requested-With": "XMLHttpRequest",
	}

	// Check common API paths
	for _, path := range apiPaths {
		apiURL := common.BuildURLPath(target, path)
		resp, err := s.client.Get(apiURL, headers)
		
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyContent := string(bodyBytes)
		
		// Check if response is JSON
		var jsonResponse interface{}
		isJSON := json.Unmarshal(bodyBytes, &jsonResponse) == nil
		
		// Check if it's an API endpoint
		if resp.StatusCode != 404 {
			detail := fmt.Sprintf("Found potential API endpoint: %s (Status: %d)", path, resp.StatusCode)
			
			// Detect response type and add more details
			if isJSON {
				detail += " - Returns JSON response"
			} else if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
				detail += " - Content-Type is application/json"
			}
			
			// Try to determine if it's a Laravel API
			isLaravelAPI := false
			
			// Check for Laravel specific headers or cookies
			for _, cookie := range resp.Cookies() {
				if strings.Contains(strings.ToLower(cookie.Name), "laravel") || 
				   strings.Contains(strings.ToLower(cookie.Name), "xsrf") {
					isLaravelAPI = true
					detail += " - Laravel cookie detected"
					break
				}
			}
			
			// Check for Laravel specific JSON structure
			if strings.Contains(bodyContent, "\"message\"") || strings.Contains(bodyContent, "\"errors\"") {
				detail += " - Laravel-style response structure"
				isLaravelAPI = true
			}
			
			// Add to results if it's likely a Laravel API endpoint
			if isJSON || isLaravelAPI || strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel API endpoint discovered",
					Path:        path,
					StatusCode:  resp.StatusCode,
					Detail:      detail,
					Severity:    "medium",
				})
			}
		}
	}
	
	// Check for API documentation
	for _, path := range docPaths {
		docURL := common.BuildURLPath(target, path)
		resp, err := customClient.Get(docURL)
		
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			bodyContent := string(bodyBytes)
			
			// Check if it looks like API documentation
			if (strings.Contains(bodyContent, "swagger") || 
				strings.Contains(bodyContent, "OpenAPI") || 
				strings.Contains(bodyContent, "API") && strings.Contains(bodyContent, "documentation")) ||
				regexp.MustCompile(`/api/v[0-9]+`).MatchString(bodyContent) {
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "API documentation discovered",
					Path:        path,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("API documentation found at %s. This can expose API structure and endpoints.", path),
					Severity:    "high",
				})
			}
		}
	}
	
	// Check for GraphQL endpoint
	graphqlPaths := []string{"/graphql", "/api/graphql"}
	for _, path := range graphqlPaths {
		graphqlURL := common.BuildURLPath(target, path)
		
		// Create a GraphQL introspection query
		introspectionQuery := `{"query":"{__schema{queryType{name}}}"}`
		
		// POST request for GraphQL introspection
		req, err := http.NewRequest("POST", graphqlURL, strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		
		resp, err := customClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		
		// Check if it's a valid GraphQL response
		var jsonResponse interface{}
		if json.Unmarshal(bodyBytes, &jsonResponse) == nil && (resp.StatusCode == 200 || resp.StatusCode == 400) {
			results = append(results, common.ScanResult{
				ScanName:    s.Name(),
				Category:    "Recon",
				Description: "GraphQL API endpoint discovered",
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("GraphQL endpoint found at %s. Consider testing for GraphQL-specific vulnerabilities.", path),
				Severity:    "high",
			})
		}
	}

	return results
}
