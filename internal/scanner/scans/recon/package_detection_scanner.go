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

// PackageDetectionScan is a struct that detects Laravel packages used by the target application
type PackageDetectionScan struct {
	client *httpclient.Client
}

// NewPackageDetectionScan initializes and returns a new PackageDetectionScan instance
func NewPackageDetectionScan() *PackageDetectionScan {
	return &PackageDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Name returns the name of the scan
func (s *PackageDetectionScan) Name() string {
	return "Laravel Package Detection"
}

// Run executes the scan to detect Laravel packages in use
func (s *PackageDetectionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Sources to check for package information
	sourceFiles := []string{
		"/composer.json",
		"/composer.lock",
		"/package.json",
		"/yarn.lock",
		"/package-lock.json",
	}

	// Package-specific paths that indicate the use of particular packages
	packagePaths := map[string][]string{
		"Laravel Debugbar": {
			"/_debugbar",
			"/_debugbar/assets/stylesheets",
			"/_debugbar/assets/javascript",
		},
		"Laravel Telescope": {
			"/telescope",
			"/telescope/requests",
			"/telescope/commands",
			"/vendor/laravel/telescope",
		},
		"Laravel Horizon": {
			"/horizon",
			"/horizon/dashboard",
			"/vendor/laravel/horizon",
		},
		"Laravel Nova": {
			"/nova",
			"/nova/dashboards",
			"/vendor/laravel/nova",
		},
		"Laravel Socialite": {
			"/login/facebook",
			"/login/google",
			"/login/github",
			"/login/twitter",
			"/auth/facebook",
			"/auth/google",
			"/auth/github",
			"/auth/twitter",
		},
		"Laravel Passport": {
			"/oauth/token",
			"/oauth/authorize",
			"/oauth/clients",
		},
		"Laravel Sanctum": {
			"/sanctum/csrf-cookie",
		},
		"Laravel Fortify": {
			"/reset-password",
			"/user/profile-information",
			"/user/password",
			"/two-factor-challenge",
		},
		"Laravel Jetstream": {
			"/user/profile",
			"/teams",
			"/team-invitations",
		},
		"Laravel Livewire": {
			"/livewire",
			"/livewire/livewire.js",
			"/livewire/livewire.min.js",
		},
		"Spatie Laravel Permission": {
			"/roles",
			"/permissions",
		},
		"Laravel Mix": {
			"/mix-manifest.json",
		},
		"Inertia.js": {
			"/js/app.js", // Check content for Inertia
		},
		"Laravel Scout": {
			"/search", // Common path for search functionality
		},
	}

	// Setup custom transport with TLS skip verification
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	customClient := &http.Client{
		Transport: customTransport,
		Timeout:   10 * time.Second,
	}

	// First, check composer files to detect packages
	packagesFound := make(map[string]string) // package name -> version

	for _, file := range sourceFiles {
		fileURL := common.BuildURLPath(target, file)
		resp, err := customClient.Get(fileURL)
		
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
			
			// Parse composer.json and composer.lock files
			if file == "/composer.json" || file == "/composer.lock" {
				parseComposerFile(file, bodyContent, packagesFound)
			}
			
			// Parse package.json, package-lock.json, and yarn.lock files for frontend packages
			if file == "/package.json" || file == "/package-lock.json" || file == "/yarn.lock" {
				parseFrontendPackageFile(file, bodyContent, packagesFound)
			}
			
			// Add a result for the exposed dependency file
			results = append(results, common.ScanResult{
				ScanName:    s.Name(),
				Category:    "Recon",
				Description: "Dependency file exposed",
				Path:        file,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("Dependency file %s is publicly accessible, revealing package information", file),
				Severity:    "medium",
			})
		}
	}

	// Add results for found packages from dependency files
	for pkg, version := range packagesFound {
		detail := fmt.Sprintf("Detected package: %s", pkg)
		if version != "" {
			detail += fmt.Sprintf(", version: %s", version)
		}
		
		// Add vulnerability information based on known issues
		vulnerabilityInfo := getPackageVulnerabilityInfo(pkg, version)
		if vulnerabilityInfo != "" {
			detail += ". " + vulnerabilityInfo
		}
		
		results = append(results, common.ScanResult{
			ScanName:    s.Name(),
			Category:    "Recon",
			Description: "Laravel package detected",
			Path:        "",
			Detail:      detail,
			Severity:    determineSeverityForPackage(pkg, version, vulnerabilityInfo != ""),
		})
	}

	// Next, check package-specific paths to confirm usage
	for packageName, paths := range packagePaths {
		for _, path := range paths {
			packageURL := common.BuildURLPath(target, path)
			resp, err := customClient.Get(packageURL)
			
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			
			// If path exists and returns a successful status code
			if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 301 {
				// Check if we already detected this package from dependency files
				if _, exists := packagesFound[packageName]; !exists {
					// Sadece varlığını kontrol ediyoruz, içeriği okumaya gerek yok
					
					// Add package detection result
					results = append(results, common.ScanResult{
						ScanName:    s.Name(),
						Category:    "Recon",
						Description: "Laravel package detected",
						Path:        path,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("Detected %s package based on characteristic URL path", packageName),
						Severity:    determineSeverityForPackage(packageName, "", false),
					})
					
					// No need to check other paths for this package
					break
				}
			}
		}
	}

	// Look for additional signs of packages in HTML/JS responses
	// Check the main page and a few common pages
	pagesToCheck := []string{
		"/",
		"/home",
		"/login",
		"/dashboard",
	}
	
	for _, page := range pagesToCheck {
		pageURL := common.BuildURLPath(target, page)
		resp, err := customClient.Get(pageURL)
		
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
			
			// Check for Livewire
			if !packageAlreadyDetected(packagesFound, "Laravel Livewire") && 
			   (strings.Contains(bodyContent, "livewire:") || 
			    strings.Contains(bodyContent, "wire:model") || 
				strings.Contains(bodyContent, "Livewire.")) {
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel package detected",
					Path:        page,
					StatusCode:  resp.StatusCode,
					Detail:      "Detected Laravel Livewire usage in page content",
					Severity:    "medium",
				})
			}
			
			// Check for Inertia.js
			if !packageAlreadyDetected(packagesFound, "Inertia.js") && 
			   (strings.Contains(bodyContent, "inertia") || 
			    strings.Contains(bodyContent, "Inertia.")) {
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel package detected",
					Path:        page,
					StatusCode:  resp.StatusCode,
					Detail:      "Detected Inertia.js usage in page content",
					Severity:    "medium",
				})
			}
			
			// Check for Alpine.js (commonly used with Laravel)
			if !packageAlreadyDetected(packagesFound, "Alpine.js") && 
			   (strings.Contains(bodyContent, "x-data") || 
			    strings.Contains(bodyContent, "Alpine.")) {
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel package detected",
					Path:        page,
					StatusCode:  resp.StatusCode,
					Detail:      "Detected Alpine.js usage in page content",
					Severity:    "low",
				})
			}
			
			// Check for Laravel Echo
			if !packageAlreadyDetected(packagesFound, "Laravel Echo") && 
			   (strings.Contains(bodyContent, "Echo.") || 
			    strings.Contains(bodyContent, "window.Echo")) {
				
				results = append(results, common.ScanResult{
					ScanName:    s.Name(),
					Category:    "Recon",
					Description: "Laravel package detected",
					Path:        page,
					StatusCode:  resp.StatusCode,
					Detail:      "Detected Laravel Echo usage in page content",
					Severity:    "medium",
				})
			}
		}
	}

	return results
}

// parseComposerFile parses composer.json and composer.lock files to extract package information
func parseComposerFile(filePath, content string, packagesFound map[string]string) {
	// For composer.json
	if filePath == "/composer.json" {
		var composerJSON map[string]interface{}
		if err := json.Unmarshal([]byte(content), &composerJSON); err == nil {
			// Check for "require" section
			if require, ok := composerJSON["require"].(map[string]interface{}); ok {
				for pkg, version := range require {
					if versionStr, ok := version.(string); ok {
						// Only track Laravel-related packages
						if strings.Contains(pkg, "laravel") || 
						   strings.Contains(pkg, "livewire") || 
						   strings.Contains(pkg, "inertia") || 
						   strings.Contains(pkg, "spatie") {
							packagesFound[pkg] = versionStr
						}
					}
				}
			}
		}
	}
	
	// For composer.lock
	if filePath == "/composer.lock" {
		var composerLock map[string]interface{}
		if err := json.Unmarshal([]byte(content), &composerLock); err == nil {
			// Check for "packages" section
			if packages, ok := composerLock["packages"].([]interface{}); ok {
				for _, pkg := range packages {
					if pkgMap, ok := pkg.(map[string]interface{}); ok {
						name, nameOk := pkgMap["name"].(string)
						version, versionOk := pkgMap["version"].(string)
						
						if nameOk && (strings.Contains(name, "laravel") || 
									 strings.Contains(name, "livewire") || 
									 strings.Contains(name, "inertia") || 
									 strings.Contains(name, "spatie")) {
							if versionOk {
								packagesFound[name] = version
							} else {
								packagesFound[name] = ""
							}
						}
					}
				}
			}
		}
	}
}

// parseFrontendPackageFile parses frontend package files to extract Laravel-related packages
func parseFrontendPackageFile(filePath, content string, packagesFound map[string]string) {
	frontendPackages := []string{
		"laravel-mix",
		"@inertiajs",
		"livewire",
		"alpinejs",
		"laravel-echo",
		"laravel-vite",
		"blade-ui-kit",
		"@livewire",
		"tailwindcss",
	}
	
	// For package.json
	if filePath == "/package.json" {
		var packageJSON map[string]interface{}
		if err := json.Unmarshal([]byte(content), &packageJSON); err == nil {
			// Check dependencies
			if dependencies, ok := packageJSON["dependencies"].(map[string]interface{}); ok {
				for pkg, version := range dependencies {
					if versionStr, ok := version.(string); ok {
						for _, frontendPkg := range frontendPackages {
							if strings.Contains(pkg, frontendPkg) {
								packagesFound[pkg] = versionStr
							}
						}
					}
				}
			}
			
			// Check devDependencies
			if devDependencies, ok := packageJSON["devDependencies"].(map[string]interface{}); ok {
				for pkg, version := range devDependencies {
					if versionStr, ok := version.(string); ok {
						for _, frontendPkg := range frontendPackages {
							if strings.Contains(pkg, frontendPkg) {
								packagesFound[pkg] = versionStr
							}
						}
					}
				}
			}
		}
	}
	
	// For yarn.lock and package-lock.json, use simple regex matching approach
	if filePath == "/yarn.lock" || filePath == "/package-lock.json" {
		for _, frontendPkg := range frontendPackages {
			// Look for the package name with a version pattern
			pattern := regexp.MustCompile(fmt.Sprintf(`"%s[@^~]?([^"]+)"`, regexp.QuoteMeta(frontendPkg)))
			matches := pattern.FindStringSubmatch(content)
			if len(matches) > 1 {
				packagesFound[frontendPkg] = matches[1]
			}
		}
	}
}

// packageAlreadyDetected checks if a package has already been detected
func packageAlreadyDetected(packagesFound map[string]string, packageName string) bool {
	for pkg := range packagesFound {
		if strings.Contains(pkg, strings.ToLower(packageName)) {
			return true
		}
	}
	return false
}

// determineSeverityForPackage determines the severity of a detected package
func determineSeverityForPackage(packageName, version string, hasVulnerability bool) string {
	// If the package has a known vulnerability, it's high severity
	if hasVulnerability {
		return "high"
	}
	
	// Check for version-specific severity (older versions might be more vulnerable)
	if version != "" {
		// Eğer versiyon çok eskiyse (örneğin: semver kontrolü yapılabilir)
		if strings.HasPrefix(version, "1.") || strings.HasPrefix(version, "0.") {
			return "medium" // Eski sürümler orta seviye risk olarak değerlendirilir
		}
	}
	
	// Debug packages are higher severity because they can leak information
	if strings.Contains(packageName, "debug") || 
	   strings.Contains(packageName, "telescope") || 
	   strings.Contains(packageName, "debugbar") {
		return "high"
	}
	
	// Authentication packages are medium severity
	if strings.Contains(packageName, "auth") || 
	   strings.Contains(packageName, "passport") || 
	   strings.Contains(packageName, "sanctum") || 
	   strings.Contains(packageName, "fortify") || 
	   strings.Contains(packageName, "socialite") {
		return "medium"
	}
	
	// UI packages are lower severity
	if strings.Contains(packageName, "ui") || 
	   strings.Contains(packageName, "blade") || 
	   strings.Contains(packageName, "tailwind") || 
	   strings.Contains(packageName, "alpine") {
		return "low"
	}
	
	// Default severity for other packages
	return "info"
}

// getPackageVulnerabilityInfo returns information about known vulnerabilities for a package
func getPackageVulnerabilityInfo(packageName, version string) string {
	// This is a simplified version - in a real scanner, you would connect to a CVE database
	
	// Check for Laravel Framework vulnerabilities (examples)
	if strings.Contains(packageName, "laravel/framework") {
		// Example vulnerability checks
		if version != "" {
			if strings.HasPrefix(version, "5.") || strings.HasPrefix(version, "6.") {
				return "Older Laravel version with potential security issues. Consider upgrading."
			}
			if strings.HasPrefix(version, "7.") && !strings.Contains(version, "7.30.4") {
				return "Laravel 7.x before 7.30.4 has known vulnerabilities. Update to latest patch version."
			}
			if strings.HasPrefix(version, "8.") && !strings.Contains(version, "8.83.") {
				return "Laravel 8.x has vulnerabilities fixed in 8.83+. Consider updating."
			}
		}
	}
	
	// Check for Laravel Debugbar vulnerabilities
	if strings.Contains(packageName, "barryvdh/laravel-debugbar") {
		return "Debug information exposure risk in production environment. Should be disabled in production."
	}
	
	// Check for Laravel Telescope vulnerabilities
	if strings.Contains(packageName, "laravel/telescope") {
		return "Monitoring tool that could expose sensitive application data. Should be secured in production."
	}
	
	// No known vulnerability information
	return ""
}
