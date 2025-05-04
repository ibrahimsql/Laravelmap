// cmd/larascan/main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"laravelmap/internal/scanner"
	"laravelmap/pkg/wafcheck"
)

// printBanner prints the application banner
func printBanner() {
	banner := `
_______________________________________________________________

 _                              _      __  __             
| |    __ _ _ __ __ _____   ___| |    |  \/  | __ _ _ __  
| |   / _  | '__/ _  \ \ / / _ \ |    | |\/| |/ _  | '_ \ 
| |__| (_| | | | (_| |\ V /  __/ |    | |  | | (_| | |_) |
|_____\__,_|_|  \__,_| \_/ \___|_|    |_|  |_|\__,_| .__/ 
                                                   |_|    
         Laravel Security Scanner by @ibrahimsql
                         Version 1.1.1
       Enterprise-Grade Laravel Penetration Testing Tool
_______________________________________________________________
`
	fmt.Println(banner)
}

func main() {
	// Print banner
	printBanner()

	// Basic parameters
	url := flag.String("url", "", "Target URL to scan")
	threads := flag.Int("threads", 5, "Number of parallel threads")
	timeout := flag.Int("timeout", 30, "Timeout in seconds for HTTP requests")
	output := flag.String("output", "", "Output file path for scan results (default: stdout)")
	format := flag.String("format", "text", "Output format: text, json, html, or pdf")

	// Scan mode and scope
	mode := flag.String("mode", "active", "Scan mode: passive or active")
	riskLevel := flag.String("risk-level", "medium", "Risk level: low, medium, or high")
	scanCategories := flag.String("categories", "all", "Scan categories to run (comma-separated): recon,vulnerabilities,waf,all")

	// WAF detection and bypass options
	wafDetection := flag.Bool("waf-detection", false, "Enable WAF detection")
	wafBypass := flag.Bool("waf-bypass", false, "Attempt to bypass detected WAFs")
	wafPayload := flag.String("waf-payload", "<script>alert(1)</script>", "Payload to use for WAF bypass attempts")
	wafRandomUA := flag.Bool("waf-random-ua", true, "Use random User-Agent headers for WAF detection/bypass")
	wafPathMutations := flag.Bool("waf-path-mutations", true, "Use path mutations for WAF bypass attempts")

	// Authentication parameters
	authMethod := flag.String("auth-method", "", "Authentication method: form, basic, token")
	authUser := flag.String("auth-user", "", "Username for authentication")
	authPass := flag.String("auth-pass", "", "Password for authentication")
	authURL := flag.String("auth-url", "", "Login URL for form-based authentication")
	authToken := flag.String("auth-token", "", "Token for token-based authentication")

	// HTTP parameters
	userAgent := flag.String("user-agent", "LaravelMap Security Scanner", "Custom User-Agent header")
	headers := flag.String("headers", "", "Custom HTTP headers (format: 'Header1:Value1,Header2:Value2')")
	cookies := flag.String("cookies", "", "Custom cookies (format: 'name1=value1,name2=value2')")
	followRedirects := flag.Bool("follow-redirects", true, "Follow HTTP redirects")

	// Scan scope
	maxDepth := flag.Int("max-depth", 3, "Maximum crawling depth")
	excludePaths := flag.String("exclude", "", "Paths to exclude from scanning (comma-separated)")
	includePaths := flag.String("include", "", "Only scan these paths (comma-separated)")

	// Other parameters
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug mode")
	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	// Display version information and exit
	if *version {
		fmt.Println("LaravelMap Security Scanner v1.0.0")
		os.Exit(0)
	}

	if *url == "" {
		fmt.Println("Please provide a target URL using the --url flag.")
		flag.Usage()
		os.Exit(1)
	}

	if *threads <= 0 {
		fmt.Println("Number of threads must be greater than 0.")
		os.Exit(1)
	}

	// Set scan categories
	categories := []string{}
	if *scanCategories == "all" {
		categories = []string{"recon", "vulnerabilities", "waf"}
	} else {
		categories = strings.Split(*scanCategories, ",")
	}

	// Enable WAF detection if specified in categories
	for _, category := range categories {
		if category == "waf" {
			*wafDetection = true
			break
		}
	}

	// Note: The categories variable will be assigned to scanConfig.Categories below

	// Set HTTP headers
	customHeaders := make(map[string]string)
	if *headers != "" {
		headerPairs := strings.Split(*headers, ",")
		for _, pair := range headerPairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Add User-Agent header
	customHeaders["User-Agent"] = *userAgent

	// Add cookies
	if *cookies != "" {
		customHeaders["Cookie"] = *cookies
	}

	// Set excluded paths
	excludedPaths := []string{}
	if *excludePaths != "" {
		excludedPaths = strings.Split(*excludePaths, ",")
	}

	// Set included paths
	includedPaths := []string{}
	if *includePaths != "" {
		includedPaths = strings.Split(*includePaths, ",")
	}

	// Create authentication configuration
	authConfig := map[string]string{
		"method": *authMethod,
		"user":   *authUser,
		"pass":   *authPass,
		"url":    *authURL,
		"token":  *authToken,
	}

	// Create scan configuration
	scanConfig := scanner.ScanConfig{
		Threads:         *threads,
		Timeout:         time.Duration(*timeout) * time.Second,
		Mode:            *mode,
		RiskLevel:       *riskLevel,
		Categories:      categories,
		Headers:         customHeaders,
		ExcludePaths:    excludedPaths,
		IncludePaths:    includedPaths,
		FollowRedirects: *followRedirects,
		MaxDepth:        *maxDepth,
		AuthConfig:      authConfig,
		Verbose:         *verbose,
		Debug:           *debug,
	}

	fmt.Println("Starting scans...")

	// Create scanner and set configuration
	sc := scanner.NewScanner()
	sc.SetConfig(scanConfig)

	// Run scans
	scanResults := sc.RunScans(*url, *threads)

	// Run WAF detection if enabled
	if *wafDetection {
		fmt.Println("\nRunning WAF detection...")

		// Initialize WAF checker
		checker := wafcheck.NewWAFChecker(
			wafcheck.WithTimeout(time.Duration(*timeout) * time.Second),
		)

		// Detect WAFs
		var detectedWAFs []wafcheck.WAFInfo

		// Perform signature-based detection
		signatureWAFs, err := checker.CheckBySignature(*url)
		if err != nil {
			fmt.Printf("[!] Error during signature-based WAF detection: %v\n", err)
		} else {
			detectedWAFs = append(detectedWAFs, signatureWAFs...)
		}

		// Perform active probing if no WAFs detected yet
		if len(detectedWAFs) == 0 {
			probeWAFs, err := checker.CheckByActiveProbing(*url)
			if err != nil {
				fmt.Printf("[!] Error during active WAF probing: %v\n", err)
			} else {
				detectedWAFs = append(detectedWAFs, probeWAFs...)
			}
		}

		// Print detection results
		if len(detectedWAFs) == 0 {
			fmt.Println("[+] No WAFs detected! Target might be unprotected.")
		} else {
			fmt.Printf("[!] Detected %d WAF(s):\n", len(detectedWAFs))
			for i, waf := range detectedWAFs {
				fmt.Printf("    %d. %s (Confidence: %d%%)\n", i+1, waf.Type, waf.Confidence)
				if *verbose {
					fmt.Printf("       Fingerprint: %s\n", waf.Fingerprint)
					if waf.BypassTips != "" {
						fmt.Printf("       Bypass Tips: %s\n", waf.BypassTips)
					}
				}
			}

			// Add WAF detection results to scan results
			for _, waf := range detectedWAFs {
				scanResults = append(scanResults, scanner.ScanResult{
					Category:    "waf",
					ScanName:    "WAF Detection",
					Path:        *url,
					Description: fmt.Sprintf("Detected %s WAF (Confidence: %d%%)", waf.Type, waf.Confidence),
					Detail:      waf.Fingerprint,
					Severity:    "info",
					StatusCode:  200,
				})
			}

			// Attempt bypass if requested and WAFs were detected
			if *wafBypass && len(detectedWAFs) > 0 {
				fmt.Println("\n[*] Attempting WAF bypass...")

				// Initialize bypasser
				bypasser := wafcheck.NewBypasser(
					wafcheck.WithRandomUserAgent(*wafRandomUA),
					wafcheck.WithPathMutations(*wafPathMutations),
				)

				// Try to bypass each detected WAF
				for _, waf := range detectedWAFs {
					fmt.Printf("[*] Attempting to bypass %s...\n", waf.Type)

					results, err := bypasser.AttemptBypass(*url, &waf, *wafPayload)
					if err != nil {
						fmt.Printf("[!] Error during bypass attempt: %v\n", err)
						continue
					}

					// Print successful bypasses
					successCount := 0
					for _, res := range results {
						if res.Success {
							successCount++
							fmt.Printf("[+] Successful bypass using %s technique!\n", res.Technique)
							if *verbose {
								fmt.Printf("    Status Code: %d\n", res.StatusCode)
								fmt.Printf("    Response Length: %d bytes\n", res.ResponseLength)
								fmt.Printf("    Notes: %s\n", res.Notes)
							}

							// Add bypass result to scan results
							scanResults = append(scanResults, scanner.ScanResult{
								Category:    "waf",
								ScanName:    "WAF Bypass",
								Path:        *url,
								Description: fmt.Sprintf("Successful bypass of %s WAF using %s technique", waf.Type, res.Technique),
								Detail:      res.Notes,
								Severity:    "high",
								StatusCode:  res.StatusCode,
							})
						}
					}

					if successCount == 0 {
						fmt.Printf("[!] No successful bypasses found for %s\n", waf.Type)
					} else {
						fmt.Printf("[+] Found %d successful bypass techniques for %s\n", successCount, waf.Type)
					}
				}
			}
		}
	}

	// Stop scan for non-Laravel sites
	for _, result := range scanResults {
		if result.Category == "error" && strings.Contains(result.Description, "Scan Aborted") {
			fmt.Printf("[%s] [%s] \nPath: %s \nDetails: %s (Status Code: %d). %s \n\n",
				result.Category, result.ScanName, result.Path, result.Description, result.StatusCode, result.Detail)
			fmt.Println("Scan completed!")
			return
		}
	}

	// Display or write results to file
	if *output != "" {
		// Write to file
		outputResults(scanResults, *output, *format)
	} else {
		// Display on standard output
		for _, result := range scanResults {
			fmt.Printf("[%s] [%s] \nPath: %s \nDetails: %s (Status Code: %d). %s \n\n",
				result.Category, result.ScanName, result.Path, result.Description, result.StatusCode, result.Detail)
		}
	}

	fmt.Println("Scan completed!")
}

// outputResults writes results to file in specified format
func outputResults(results []scanner.ScanResult, outputPath string, format string) {
	switch format {
	case "json":
		// Write in JSON format
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Printf("Error generating JSON report: %v\n", err)
			return
		}
		err = ioutil.WriteFile(outputPath, jsonData, 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}
	case "html":
		// Write in HTML format (simple example)
		var htmlContent strings.Builder
		htmlContent.WriteString("<html><head><title>LaravelMap Scan Report</title>")
		htmlContent.WriteString("<style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background-color:#f2f2f2}</style>")
		htmlContent.WriteString("</head><body><h1>LaravelMap Security Scan Report</h1>")
		htmlContent.WriteString("<table><tr><th>Category</th><th>Scan</th><th>Path</th><th>Description</th><th>Status Code</th><th>Details</th><th>Severity</th></tr>")

		for _, result := range results {
			htmlContent.WriteString("<tr>")
			htmlContent.WriteString(fmt.Sprintf("<td>%s</td>", result.Category))
			htmlContent.WriteString(fmt.Sprintf("<td>%s</td>", result.ScanName))
			htmlContent.WriteString(fmt.Sprintf("<td>%s</td>", result.Path))
			htmlContent.WriteString(fmt.Sprintf("<td>%s</td>", result.Description))
			htmlContent.WriteString(fmt.Sprintf("<td>%d</td>", result.StatusCode))
			htmlContent.WriteString(fmt.Sprintf("<td>%s</td>", result.Detail))
			htmlContent.WriteString(fmt.Sprintf("<td>%s</td>", result.Severity))
			htmlContent.WriteString("</tr>")
		}

		htmlContent.WriteString("</table></body></html>")
		err := ioutil.WriteFile(outputPath, []byte(htmlContent.String()), 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}
	default:
		// Write in text format
		var textContent strings.Builder
		textContent.WriteString("LaravelMap Security Scan Report\n")
		textContent.WriteString("===============================\n\n")

		for _, result := range results {
			textContent.WriteString(fmt.Sprintf("[%s] [%s]\n", result.Category, result.ScanName))
			textContent.WriteString(fmt.Sprintf("Path: %s\n", result.Path))
			textContent.WriteString(fmt.Sprintf("Description: %s (Status Code: %d)\n", result.Description, result.StatusCode))
			textContent.WriteString(fmt.Sprintf("Details: %s\n", result.Detail))
			textContent.WriteString(fmt.Sprintf("Severity: %s\n\n", result.Severity))
		}

		err := ioutil.WriteFile(outputPath, []byte(textContent.String()), 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}
	}

	fmt.Printf("Results written to %s in %s format\n", outputPath, format)
}
