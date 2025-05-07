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

// ConfigLeakageScan is a struct that discovers configuration and .env leakage in Laravel apps
type ConfigLeakageScan struct {
	client *httpclient.Client
}

// NewConfigLeakageScan initializes and returns a new ConfigLeakageScan instance
func NewConfigLeakageScan() *ConfigLeakageScan {
	return &ConfigLeakageScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Name returns the name of the scan
func (s *ConfigLeakageScan) Name() string {
	return "Laravel Config Leakage Scanner"
}

// Run executes the scan to discover Laravel config leakage
func (s *ConfigLeakageScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Potential config file paths in Laravel
	configPaths := []string{
		"/.env",
		"/.env.backup",
		"/.env.save",
		"/.env.old",
		"/.env.bak",
		"/.env.dev",
		"/.env.production",
		"/.env.local",
		"/.env.example",
		"/config/app.php",
		"/config/database.php",
		"/config/auth.php",
		"/storage/logs/laravel.log",
		"/storage/logs/laravel-error.log",
		"/storage/logs/debug.log",
		"/storage/logs/error.log",
		"/storage/framework/cache",
		"/storage/framework/sessions",
		"/composer.json",
		"/composer.lock",
		"/package.json",
		"/yarn.lock",
		"/webpack.mix.js",
		"/artisan",
		"/phpunit.xml",
		"/backup.zip",
		"/backup.tar.gz",
		"/backup.sql",
		"/laravel.sql",
		"/database.sql",
		"/db.sql",
	}

	// Setup custom transport with TLS skip verification
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	customClient := &http.Client{
		Transport: customTransport,
		Timeout:   10 * time.Second,
	}

	// Check for config leaks
	for _, path := range configPaths {
		configURL := common.BuildURLPath(target, path)
		
		// Create request
		req, err := http.NewRequest("GET", configURL, nil)
		if err != nil {
			continue
		}
		
		// Add common headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
		
		// Send request
		resp, err := customClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// If file exists
		if resp.StatusCode == 200 {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			bodyContent := string(bodyBytes)
			
			// Determine if the content seems to be a configuration file
			isConfig, severity, detail := analyzeConfigContent(path, bodyContent)
			
			if isConfig {
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel configuration file exposed",
					Path:        path,
					StatusCode:  resp.StatusCode,
					Detail:      detail,
					Severity:    severity,
				})
			}
		}
	}
	
	// Check for git exposure
	gitPaths := []string{"/.git/config", "/.git/HEAD", "/.gitignore"}
	for _, path := range gitPaths {
		gitURL := common.BuildURLPath(target, path)
		resp, err := customClient.Get(gitURL)
		
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			results = append(results, common.ScanResult{
				ScanName:    s.Name(),
				Category:    "Recon",
				Description: "Git repository information exposed",
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("Git repository information exposed at %s. This could leak source code and sensitive data.", path),
				Severity:    "critical",
			})
		}
	}

	return results
}

// analyzeConfigContent analyzes the content of a potential config file
func analyzeConfigContent(path string, content string) (bool, string, string) {
	// .env file patterns
	if strings.HasSuffix(path, ".env") || strings.Contains(path, ".env.") {
		// Check if it looks like a real .env file
		if strings.Contains(content, "DB_CONNECTION") || 
		   strings.Contains(content, "APP_KEY=") || 
		   strings.Contains(content, "APP_ENV=") ||
		   regexp.MustCompile(`[A-Z_]+=.+`).MatchString(content) {
			
			// Look for sensitive credentials
			sensitiveData := []string{}
			
			// Database credentials
			if strings.Contains(content, "DB_PASSWORD=") && !strings.Contains(content, "DB_PASSWORD=null") {
				sensitiveData = append(sensitiveData, "Database password")
			}
			
			// API keys
			apiKeyPattern := regexp.MustCompile(`(?i)(_KEY|API_|TOKEN|SECRET)=[^${\r\n]+`)
			if apiKeyPattern.MatchString(content) {
				sensitiveData = append(sensitiveData, "API keys/tokens")
			}
			
			// AWS credentials
			if strings.Contains(content, "AWS_") {
				sensitiveData = append(sensitiveData, "AWS credentials")
			}
			
			// SMTP credentials
			if strings.Contains(content, "MAIL_PASSWORD=") && !strings.Contains(content, "MAIL_PASSWORD=null") {
				sensitiveData = append(sensitiveData, "SMTP credentials")
			}
			
			severity := "high"
			if len(sensitiveData) > 0 {
				severity = "critical"
			}
			
			detail := "Exposed .env file containing environment configuration"
			if len(sensitiveData) > 0 {
				detail += ". Found sensitive data: " + strings.Join(sensitiveData, ", ")
			}
			
			return true, severity, detail
		}
	}
	
	// Check for log files
	if strings.Contains(path, "log") || strings.HasSuffix(path, ".log") {
		if strings.Contains(content, "Stack trace:") || 
		   strings.Contains(content, "ErrorException") || 
		   strings.Contains(content, "Laravel") ||
		   regexp.MustCompile(`\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]`).MatchString(content) {
			
			// Scan for potentially sensitive information in logs
			sensitiveInfo := false
			if regexp.MustCompile(`(password|token|api_key|secret|pwd|pass)=`).MatchString(content) {
				sensitiveInfo = true
			}
			
			severity := "medium"
			if sensitiveInfo {
				severity = "high"
			}
			
			detail := "Exposed Laravel log file"
			if sensitiveInfo {
				detail += " potentially containing sensitive information like passwords or tokens"
			}
			
			return true, severity, detail
		}
	}
	
	// Composer files that reveal dependencies
	if path == "/composer.json" || path == "/composer.lock" {
		if strings.Contains(content, "laravel/framework") {
			return true, "medium", "Exposed Composer file revealing Laravel dependencies and versions"
		}
	}
	
	// Check for Laravel Artisan
	if path == "/artisan" {
		if strings.Contains(content, "Illuminate") || strings.Contains(content, "Laravel") {
			return true, "medium", "Exposed Laravel Artisan console script"
		}
	}
	
	// Database dumps
	if strings.HasSuffix(path, ".sql") {
		if strings.Contains(content, "INSERT INTO") || strings.Contains(content, "CREATE TABLE") {
			return true, "critical", "Exposed database dump file that may contain sensitive data"
		}
	}
	
	// Backup files
	if strings.Contains(path, "backup") || strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar.gz") {
		return true, "high", "Exposed backup file that may contain sensitive data"
	}
	
	// Default values for non-matching content
	return false, "", ""
}
