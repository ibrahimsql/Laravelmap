package scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/internal/scanner/scans/recon"
	"laravelmap/internal/scanner/scans/vulnerabilities"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ScanConfig represents the configuration for the scanner
type ScanConfig struct {
	Threads         int
	Timeout         time.Duration
	Mode            string
	RiskLevel       string
	Categories      []string
	Headers         map[string]string
	ExcludePaths    []string
	IncludePaths    []string
	FollowRedirects bool
	MaxDepth        int
	AuthConfig      map[string]string
	Verbose         bool
	Debug           bool
	IgnoreSSL       bool
	UserAgent       string
	Cookies         string
	Proxy           string
	OutputFormat    string
	OutputFile      string
	ScanDelay       time.Duration
	Concurrency     int
	MaxRetries      int
	StatusCodes     []int
}

// ScanResult is an alias for common.ScanResult
// This allows direct access to scanner.ScanResult in main.go
type ScanResult = common.ScanResult

type Scanner struct {
	scans  map[string][]common.Scan
	config ScanConfig
	client *http.Client
}

func NewScanner() *Scanner {
	return &Scanner{
		scans: map[string][]common.Scan{
			"recon": {
				recon.NewFrameworkDetectionScan(),
				recon.NewLaravelVersionScan(),
				recon.NewLivewireScan(),
				recon.NewPhpVersionScan(),
				recon.NewSubdomainEnumScan(),
				recon.NewHostHeaderInjectionScan(),
				recon.NewRouteDiscoveryScan(),
				recon.NewAPIEndpointsScan(),
				recon.NewConfigLeakageScan(),
				recon.NewPackageDetectionScan(),
			},
			"vulnerabilities": {
				vulnerabilities.NewCsrfTokenScan(),
				vulnerabilities.NewDebugModeScan(),
				vulnerabilities.NewSensitiveFilesScan(),
				vulnerabilities.NewToolsDetectionScan(),
				vulnerabilities.NewSQLInjectionScan(),
				vulnerabilities.NewXSSScanner(),
				vulnerabilities.NewCSRFBypassScanner(),
				vulnerabilities.NewFileUploadScanner(),
				vulnerabilities.NewDeserializationScanner(),
				vulnerabilities.NewMassAssignmentScanner(),
				vulnerabilities.NewAuthorizationBypassScanner(),
				vulnerabilities.NewRateLimitingBypassScanner(),
				vulnerabilities.NewLogInjectionScanner(),
				vulnerabilities.NewQueueExploitationScanner(),
				vulnerabilities.NewEventSystemScanner(),
				vulnerabilities.NewNotificationVulnerabilitiesScanner(),
				vulnerabilities.NewBroadcastingVulnerabilitiesScanner(),
				vulnerabilities.NewSchedulerVulnerabilitiesScanner(),
				vulnerabilities.NewCachePoisoningScanner(),
				vulnerabilities.NewLaravelModuleScanner(),
				vulnerabilities.NewSanctumFortifyScanner(),
				vulnerabilities.NewJetstreamScanner(),
				vulnerabilities.NewLaravelEchoScanner(),
				vulnerabilities.NewLivewireScanner(),
				vulnerabilities.NewEloquentORMScanner(),
			},
		},
		config: ScanConfig{
			Threads:         5,
			Timeout:         30 * time.Second,
			Mode:            "active",
			RiskLevel:       "medium",
			FollowRedirects: true,
			MaxDepth:        3,
			UserAgent:       "LaravelMap Security Scanner v1.1.1",
			MaxRetries:      3,
			ScanDelay:       100 * time.Millisecond,
			StatusCodes:     []int{200, 201, 301, 302, 307, 401, 403, 404, 500},
		},
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     100,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("too many redirects")
				}
				return nil
			},
		},
	}
}

// SetConfig sets the scanner configuration
func (s *Scanner) SetConfig(config ScanConfig) {
	s.config = config

	// Configure the HTTP client
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: config.IgnoreSSL},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set proxy if configured
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	s.client = &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// RunScans executes all scans in parallel with a limit on the number of concurrent goroutines
func (s *Scanner) RunScans(target string, threads int) []common.ScanResult {
	fmt.Println("Checking if target is a Laravel application...")

	// Validate the URL
	_, err := url.Parse(target)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return []common.ScanResult{
			{
				Category:    "error",
				ScanName:    "URL Validation",
				Path:        target,
				Description: "Invalid URL format",
				Detail:      err.Error(),
				StatusCode:  0,
				Severity:    "high",
			},
		}
	}

	// Check if the target site is accessible
	resp, err := s.client.Get(target)
	if err != nil {
		fmt.Printf("Error connecting to target: %v\n", err)
		return []common.ScanResult{
			{
				Category:    "error",
				ScanName:    "Connection Check",
				Path:        target,
				Description: "Could not connect to the target",
				Detail:      err.Error(),
				StatusCode:  0,
				Severity:    "high",
			},
		}
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode >= 500 {
		fmt.Printf("Target returned server error: %d\n", resp.StatusCode)
		return []common.ScanResult{
			{
				Category:    "error",
				ScanName:    "Connection Check",
				Path:        target,
				Description: "Target server returned an error",
				Detail:      fmt.Sprintf("HTTP Status Code: %d", resp.StatusCode),
				StatusCode:  resp.StatusCode,
				Severity:    "high",
			},
		}
	}

	// Detect Laravel
	isLaravel, err := s.detectLaravel(target)
	if err != nil {
		fmt.Printf("Error during Laravel detection: %v\n", err)
		// Return an error if the site is inaccessible
		return []common.ScanResult{
			{
				Category:    "error",
				ScanName:    "Framework Detection",
				Path:        target,
				Description: "Error during Laravel detection",
				Detail:      err.Error(),
				StatusCode:  0,
				Severity:    "high",
			},
		}
	}

	if !isLaravel {
		fmt.Println("Target does not appear to be a Laravel application. Aborting scan.")
		// Return a warning if Laravel is not detected
		return []common.ScanResult{
			{
				Category:    "error",
				ScanName:    "Framework Detection",
				Path:        target,
				Description: "Scan Aborted: The remote website is up, but does not seem to be running Laravel",
				Detail:      "The target does not appear to be a Laravel application. No Laravel-specific signatures were detected.",
				StatusCode:  resp.StatusCode,
				Severity:    "info",
			},
		}
	}

	fmt.Println("Laravel detected! Starting vulnerability scans...")

	var wg sync.WaitGroup
	resultsChan := make(chan common.ScanResult, 100) // Buffered channel for results
	sem := make(chan struct{}, threads)              // Semaphore to limit concurrency

	fmt.Println("Starting scans...")

	// Only scan the selected categories
	categoriesToScan := s.config.Categories
	if len(categoriesToScan) == 0 || (len(categoriesToScan) == 1 && categoriesToScan[0] == "all") {
		// Scan all categories
		for category, scans := range s.scans {
			s.runScansForCategory(category, scans, target, &wg, sem, resultsChan)
		}
	} else {
		// Only scan the selected categories
		for _, category := range categoriesToScan {
			if scans, ok := s.scans[category]; ok {
				s.runScansForCategory(category, scans, target, &wg, sem, resultsChan)
			}
		}
	}

	// Close the results channel after all scans are done
	go func() {
		wg.Wait()
		fmt.Println("All scans completed. Closing results channel.")
		close(resultsChan)
	}()

	// Collect all results from the channel
	var allResults []common.ScanResult
	for result := range resultsChan {
		allResults = append(allResults, result)
	}

	fmt.Println("Finished collecting all results.")
	return allResults
}

// runScansForCategory runs the scans for a specific category
func (s *Scanner) runScansForCategory(category string, scans []common.Scan, target string, wg *sync.WaitGroup, sem chan struct{}, resultsChan chan<- common.ScanResult) {
	for _, scan := range scans {
		wg.Add(1)

		// Execute the scan in a goroutine
		go func(scan common.Scan, category string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			fmt.Printf("Running scan: %s\n", scan.Name())
			results := scan.Run(target)
			for _, result := range results {
				fmt.Printf("Found result in %s: %s\n", scan.Name(), result.Description)
				resultsChan <- result // Send results to channel
			}

			// Add a delay between scans
			time.Sleep(s.config.ScanDelay)
		}(scan, category)
	}
}

// detectLaravel detects if the target site is a Laravel application
func (s *Scanner) detectLaravel(target string) (bool, error) {
	fmt.Println("Starting Laravel detection...")

	// Check for Laravel indicators
	indicators := []struct {
		path   string
		header string
		body   []string
		regex  string
	}{
		{"/", "Set-Cookie", []string{"laravel_session", "XSRF-TOKEN"}, ""},
		{"/", "", []string{"Laravel", "laravel", "Illuminate", "illuminate"}, ""},
		{"/login", "", []string{"csrf-token", "_token", "Laravel", "laravel"}, ""},
		{"/", "", []string{}, `<meta\s+name=["']csrf-token["']\s+content=["'][^"']+["']`},
		{"/", "", []string{}, `<input\s+type=["']hidden["']\s+name=["']_token["']\s+value=["'][^"']+["']`},
		{"/login", "", []string{}, `<input\s+type=["']hidden["']\s+name=["']_token["']\s+value=["'][^"']+["']`},
		{"/", "X-Powered-By", []string{"PHP"}, ""},
		{"/", "Server", []string{"Apache", "nginx"}, ""},
	}

	for _, indicator := range indicators {
		urlToCheck := s.buildURL(target, indicator.path)
		fmt.Printf("Checking URL: %s\n", urlToCheck)

		req, err := http.NewRequest("GET", urlToCheck, nil)
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)

		// Add custom headers
		for key, value := range s.config.Headers {
			req.Header.Set(key, value)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			fmt.Printf("Error reading response body: %v\n", err)
			continue
		}

		bodyText := string(bodyBytes)

		// Check the status code
		fmt.Printf("Response status code: %d\n", resp.StatusCode)
		if resp.StatusCode >= 500 {
			fmt.Printf("Server error detected, skipping this check\n")
			continue
		}

		// Check the header
		if indicator.header != "" {
			for key, values := range resp.Header {
				if strings.EqualFold(key, indicator.header) {
					for _, value := range values {
						for _, bodyPattern := range indicator.body {
							if strings.Contains(strings.ToLower(value), strings.ToLower(bodyPattern)) {
								fmt.Printf("Laravel detected via header: %s contains %s\n", key, bodyPattern)
								return true, nil
							}
						}
					}
				}
			}
		}

		// Check the body
		for _, bodyPattern := range indicator.body {
			if bodyPattern != "" && strings.Contains(strings.ToLower(bodyText), strings.ToLower(bodyPattern)) {
				fmt.Printf("Laravel detected via body content: %s\n", bodyPattern)
				return true, nil
			}
		}

		// Check the regex
		if indicator.regex != "" {
			re, err := regexp.Compile(indicator.regex)
			if err != nil {
				fmt.Printf("Error compiling regex: %v\n", err)
				continue
			}

			if re.MatchString(bodyText) {
				fmt.Printf("Laravel detected via regex pattern: %s\n", indicator.regex)
				return true, nil
			}
		}
	}

	// Check for Laravel-specific files
	laravelPaths := []string{
		"/vendor/laravel",
		"/public/index.php",
		"/storage/logs",
		"/artisan",
		"/resources/views",
		"/app/Http/Controllers",
		"/bootstrap/app.php",
		"/config/app.php",
		"/routes/web.php",
		"/favicon.ico",
		"/robots.txt",
	}

	for _, path := range laravelPaths {
		urlToCheck := s.buildURL(target, strings.TrimSuffix(path, "/"))
		fmt.Printf("Checking path: %s\n", urlToCheck)

		req, err := http.NewRequest("HEAD", urlToCheck, nil)
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}
		resp.Body.Close()

		fmt.Printf("Response status code: %d\n", resp.StatusCode)
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			fmt.Printf("Laravel detected via path existence: %s (status: %d)\n", path, resp.StatusCode)
			return true, nil
		}
	}

	// Check for Laravel-specific JavaScript files
	jsPatterns := []string{
		"/js/app.js",
		"/js/bootstrap.js",
		"/js/jquery.js",
		"/js/laravel.js",
	}

	for _, pattern := range jsPatterns {
		urlToCheck := s.buildURL(target, strings.TrimSuffix(pattern, "/"))
		fmt.Printf("Checking JS file: %s\n", urlToCheck)

		req, err := http.NewRequest("HEAD", urlToCheck, nil)
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}
		resp.Body.Close()

		fmt.Printf("Response status code: %d\n", resp.StatusCode)
		if resp.StatusCode == 200 {
			fmt.Printf("Laravel detected via JS file: %s\n", pattern)
			return true, nil
		}
	}

	// Check for Laravel-specific CSS files
	cssPatterns := []string{
		"/css/app.css",
		"/css/bootstrap.css",
		"/css/laravel.css",
	}

	for _, pattern := range cssPatterns {
		urlToCheck := s.buildURL(target, strings.TrimSuffix(pattern, "/"))
		fmt.Printf("Checking CSS file: %s\n", urlToCheck)

		req, err := http.NewRequest("HEAD", urlToCheck, nil)
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}
		resp.Body.Close()

		fmt.Printf("Response status code: %d\n", resp.StatusCode)
		if resp.StatusCode == 200 {
			fmt.Printf("Laravel detected via CSS file: %s\n", pattern)
			return true, nil
		}
	}

	// Check for custom Laravel error pages
	errorPaths := []string{
		"/non-existent-page-12345",
		"/error/404",
		"/this-page-does-not-exist-123",
	}

	for _, path := range errorPaths {
		urlToCheck := s.buildURL(target, strings.TrimSuffix(path, "/"))
		fmt.Printf("Checking error path: %s\n", urlToCheck)

		req, err := http.NewRequest("GET", urlToCheck, nil)
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			fmt.Printf("Error reading response body: %v\n", err)
			continue
		}

		bodyText := string(bodyBytes)

		// Laravel error page indicators
		laravelErrorPatterns := []string{
			"Whoops, looks like something went wrong",
			"Laravel",
			"Illuminate",
			"symfony",
			"stack trace",
			"ErrorException",
			"vendor/laravel",
		}

		for _, pattern := range laravelErrorPatterns {
			if strings.Contains(strings.ToLower(bodyText), strings.ToLower(pattern)) {
				fmt.Printf("Laravel detected via error page pattern: %s\n", pattern)
				return true, nil
			}
		}
	}

	// No Laravel indicators found
	fmt.Println("No Laravel indicators found.")
	return false, nil
}

// buildURL combines the target URL and path
func (s *Scanner) buildURL(baseURL, path string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	path = strings.TrimSuffix(path, "/")

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return baseURL + path
}
