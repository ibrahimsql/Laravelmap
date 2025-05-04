package wafcheck

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/cdncheck"
)

// WAFType represents a type of WAF
type WAFType string

// Known WAF types
const (
	Cloudflare     WAFType = "Cloudflare"
	Incapsula      WAFType = "Imperva Incapsula"
	Akamai         WAFType = "Akamai Kona"
	AWSWAFv2       WAFType = "AWS WAF v2"
	F5BigIP        WAFType = "F5 BIG-IP ASM"
	Fortinet       WAFType = "FortiWeb"
	Sucuri         WAFType = "Sucuri"
	ModSecurity    WAFType = "ModSecurity"
	Wordfence      WAFType = "Wordfence"
	Barracuda      WAFType = "Barracuda"
	Fastly         WAFType = "Fastly"
	Radware        WAFType = "Radware AppWall"
	DotDefender    WAFType = "DotDefender"
	Wallarm        WAFType = "Wallarm"
	Reblaze        WAFType = "Reblaze"
	Varnish        WAFType = "Varnish"
	Distil         WAFType = "Distil Networks"
	Stackpath      WAFType = "StackPath"
	AzureFrontDoor WAFType = "Azure Front Door"
	GoogleCloud    WAFType = "Google Cloud Armor"
	Unknown        WAFType = "Unknown WAF"
)

// WAFInfo contains information about a detected WAF
type WAFInfo struct {
	Type        WAFType
	Confidence  int // 0-100
	Fingerprint string
	BypassTips  string
}

// WAFChecker is the main struct for WAF detection
type WAFChecker struct {
	httpClient  *http.Client
	ipRanges    map[WAFType][]*net.IPNet
	signatures  map[WAFType][]WAFSignature
	bypassTechs map[WAFType][]string
	cdnClient   *cdncheck.Client
	mu          sync.RWMutex
}

// WAFSignature defines a signature for detecting a WAF
type WAFSignature struct {
	Headers     map[string]string
	Cookies     map[string]string
	BodyContent []string
	StatusCodes []int
}

// Option is a function type for configuring WAFChecker
type Option func(*WAFChecker)

// WithTimeout sets the timeout for HTTP requests
func WithTimeout(timeout time.Duration) Option {
	return func(w *WAFChecker) {
		w.httpClient.Timeout = timeout
	}
}

// NewWAFChecker creates a new WAFChecker instance with options
func NewWAFChecker(options ...Option) *WAFChecker {
	checker := New()

	// Apply options
	for _, option := range options {
		option(checker)
	}

	return checker
}

// New creates a new WAFChecker instance
func New() *WAFChecker {
	// Initialize cdncheck client
	cdnClient := cdncheck.New()

	checker := &WAFChecker{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ipRanges:    make(map[WAFType][]*net.IPNet),
		signatures:  make(map[WAFType][]WAFSignature),
		bypassTechs: make(map[WAFType][]string),
		cdnClient:   cdnClient,
	}

	checker.initIPRanges()
	checker.initSignatures()
	checker.initBypassTechniques()

	return checker
}

// CheckIP checks if an IP belongs to a known WAF provider
func (w *WAFChecker) CheckIP(ip net.IP) (bool, WAFType, error) {
	// First check with cdncheck library
	isWAF, wafProvider, err := w.cdnClient.CheckWAF(ip)
	if err != nil {
		return false, Unknown, fmt.Errorf("cdncheck WAF detection error: %w", err)
	}

	if isWAF {
		// Map cdncheck provider to our WAFType
		detectedType := mapCDNCheckProviderToWAFType(wafProvider)
		return true, detectedType, nil
	}

	// If cdncheck didn't find anything, check with our custom IP ranges
	w.mu.RLock()
	defer w.mu.RUnlock()

	for wafType, ranges := range w.ipRanges {
		for _, ipRange := range ranges {
			if ipRange.Contains(ip) {
				return true, wafType, nil
			}
		}
	}

	// Also check if it's a CDN (some CDNs have WAF capabilities)
	isCDN, cdnProvider, err := w.cdnClient.CheckCDN(ip)
	if err != nil {
		return false, Unknown, fmt.Errorf("cdncheck CDN detection error: %w", err)
	}

	if isCDN {
		// Map CDN provider to potential WAF
		detectedType := mapCDNProviderToWAFType(cdnProvider)
		if detectedType != Unknown {
			return true, detectedType, nil
		}
	}

	return false, Unknown, nil
}

// DetectWAF attempts to detect WAF presence on a target URL
func (w *WAFChecker) DetectWAF(targetURL string) (*WAFInfo, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// First check if the hostname resolves to a known WAF IP
	ips, err := net.LookupIP(parsedURL.Hostname())
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if matched, wafType, _ := w.CheckIP(ip); matched {
				bypassTipsString := strings.Join(w.bypassTechs[wafType], "; ")
				return &WAFInfo{
					Type:        wafType,
					Confidence:  90,
					Fingerprint: fmt.Sprintf("IP address %s belongs to %s range", ip.String(), wafType),
					BypassTips:  bypassTipsString,
				}, nil
			}
		}
	}

	// Send a normal request to check headers
	resp, err := w.httpClient.Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Check for WAF signatures in the response
	wafInfo := w.checkResponseSignatures(resp)
	if wafInfo != nil {
		return wafInfo, nil
	}

	// If no WAF detected yet, try with malicious payloads
	return w.activeProbing(targetURL)
}

// CheckBySignature checks for WAF presence using signature-based detection
func (w *WAFChecker) CheckBySignature(targetURL string) ([]WAFInfo, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// First check if the hostname resolves to a known WAF IP
	var results []WAFInfo
	ips, err := net.LookupIP(parsedURL.Hostname())
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if matched, wafType, _ := w.CheckIP(ip); matched {
				bypassTipsString := strings.Join(w.bypassTechs[wafType], "; ")
				results = append(results, WAFInfo{
					Type:        wafType,
					Confidence:  90,
					Fingerprint: fmt.Sprintf("IP address %s belongs to %s range", ip.String(), wafType),
					BypassTips:  bypassTipsString,
				})
			}
		}
	}

	// Send a normal request to check headers
	resp, err := w.httpClient.Get(targetURL)
	if err != nil {
		return results, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Check for WAF signatures in the response
	wafInfo := w.checkResponseSignatures(resp)
	if wafInfo != nil {
		results = append(results, *wafInfo)
	}

	return results, nil
}

// CheckByActiveProbing checks for WAF presence using active probing techniques
func (w *WAFChecker) CheckByActiveProbing(targetURL string) ([]WAFInfo, error) {
	// Common attack payloads that typically trigger WAFs
	payloads := []string{
		"/?id=1' OR '1'='1",           // SQL Injection
		"/?<script>alert(1)</script>", // XSS
		"/?../../etc/passwd",          // Path Traversal
		"/?exec=/bin/bash",            // Command Injection
	}

	var results []WAFInfo

	for _, payload := range payloads {
		probeURL := targetURL + payload
		req, err := http.NewRequest("GET", probeURL, nil)
		if err != nil {
			continue
		}

		// Add some suspicious headers
		req.Header.Set("User-Agent", "sqlmap/1.4.7")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := w.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check if we triggered a WAF
		if wafInfo := w.checkResponseSignatures(resp); wafInfo != nil {
			results = append(results, *wafInfo)
			break
		}

		// Check for common WAF response codes
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 503 {
			bypassTipsString := strings.Join(w.bypassTechs[Unknown], "; ")
			results = append(results, WAFInfo{
				Type:        Unknown,
				Confidence:  50,
				Fingerprint: fmt.Sprintf("Suspicious response code %d for malicious payload", resp.StatusCode),
				BypassTips:  bypassTipsString,
			})
			break
		}
	}

	return results, nil
}

// checkResponseSignatures checks for WAF signatures in HTTP response
func (w *WAFChecker) checkResponseSignatures(resp *http.Response) *WAFInfo {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for wafType, signatures := range w.signatures {
		for _, sig := range signatures {
			confidence := 0

			// Check headers
			for headerName, headerValue := range sig.Headers {
				if value := resp.Header.Get(headerName); value != "" {
					if headerValue == "*" || strings.Contains(strings.ToLower(value), strings.ToLower(headerValue)) {
						confidence += 30
					}
				}
			}

			// Check status codes if specified
			if len(sig.StatusCodes) > 0 {
				for _, code := range sig.StatusCodes {
					if resp.StatusCode == code {
						confidence += 20
					}
				}
			}

			// If we have enough confidence, return the WAF info
			if confidence >= 30 {
				bypassTipsString := strings.Join(w.bypassTechs[wafType], "; ")
				return &WAFInfo{
					Type:        wafType,
					Confidence:  confidence,
					Fingerprint: fmt.Sprintf("Matched signature in response headers"),
					BypassTips:  bypassTipsString,
				}
			}
		}
	}

	return nil
}

// activeProbing sends malicious payloads to trigger WAF responses
func (w *WAFChecker) activeProbing(targetURL string) (*WAFInfo, error) {
	// Common attack payloads that typically trigger WAFs
	payloads := []string{
		"/?id=1' OR '1'='1",           // SQL Injection
		"/?<script>alert(1)</script>", // XSS
		"/?../../etc/passwd",          // Path Traversal
		"/?exec=/bin/bash",            // Command Injection
	}

	for _, payload := range payloads {
		probeURL := targetURL + payload
		req, err := http.NewRequest("GET", probeURL, nil)
		if err != nil {
			continue
		}

		// Add some suspicious headers
		req.Header.Set("User-Agent", "sqlmap/1.4.7")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := w.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check if we triggered a WAF
		if wafInfo := w.checkResponseSignatures(resp); wafInfo != nil {
			return wafInfo, nil
		}

		// Check for common WAF response codes
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 503 {
			return &WAFInfo{
				Type:        Unknown,
				Confidence:  50,
				Fingerprint: fmt.Sprintf("Suspicious response code %d for malicious payload", resp.StatusCode),
				BypassTips:  "Try different encoding techniques, Use HTTP header mutations",
			}, nil
		}
	}

	return nil, nil
}

// initIPRanges initializes known WAF IP ranges
func (w *WAFChecker) initIPRanges() {
	// This is a supplementary to cdncheck - we keep some additional ranges that might not be in cdncheck
	cloudflareRanges := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	}

	akamaiRanges := []string{
		"23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10",
	}

	fastlyRanges := []string{
		"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
	}

	// Add Cloudflare ranges
	var cloudflareNets []*net.IPNet
	for _, cidr := range cloudflareRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			cloudflareNets = append(cloudflareNets, ipNet)
		}
	}
	w.ipRanges[Cloudflare] = cloudflareNets

	// Add Akamai ranges
	var akamaiNets []*net.IPNet
	for _, cidr := range akamaiRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			akamaiNets = append(akamaiNets, ipNet)
		}
	}
	w.ipRanges[Akamai] = akamaiNets

	// Add Fastly ranges
	var fastlyNets []*net.IPNet
	for _, cidr := range fastlyRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			fastlyNets = append(fastlyNets, ipNet)
		}
	}
	w.ipRanges[Fastly] = fastlyNets
}

// initSignatures initializes WAF signatures
func (w *WAFChecker) initSignatures() {
	// Cloudflare signatures
	w.signatures[Cloudflare] = []WAFSignature{
		{
			Headers: map[string]string{
				"Server":          "cloudflare",
				"CF-RAY":          "*",
				"CF-Cache-Status": "*",
			},
		},
	}

	// Incapsula signatures
	w.signatures[Incapsula] = []WAFSignature{
		{
			Headers: map[string]string{
				"X-CDN":      "Incapsula",
				"X-Iinfo":    "*",
				"Set-Cookie": "visid_incap",
			},
		},
	}

	// Akamai signatures
	w.signatures[Akamai] = []WAFSignature{
		{
			Headers: map[string]string{
				"Server":               "AkamaiGHost",
				"X-Akamai-Transformed": "*",
			},
		},
	}

	// AWS WAF signatures
	w.signatures[AWSWAFv2] = []WAFSignature{
		{
			Headers: map[string]string{
				"X-AMZ-CF-ID": "*",
				"X-Cache":     "*",
			},
		},
	}

	// F5 BIG-IP signatures
	w.signatures[F5BigIP] = []WAFSignature{
		{
			Headers: map[string]string{
				"Server":     "BigIP",
				"Set-Cookie": "BIGipServer",
			},
			StatusCodes: []int{403, 406, 501},
		},
	}

	// ModSecurity signatures
	w.signatures[ModSecurity] = []WAFSignature{
		{
			Headers: map[string]string{
				"Server": "ModSecurity",
			},
			StatusCodes: []int{403, 406, 501},
		},
	}

	// Fastly signatures
	w.signatures[Fastly] = []WAFSignature{
		{
			Headers: map[string]string{
				"X-Served-By":  "cache-*",
				"X-Cache":      "*",
				"X-Cache-Hits": "*",
				"X-Timer":      "*",
			},
		},
	}

	// Add more WAF signatures as needed...
}

// initBypassTechniques initializes WAF bypass techniques
func (w *WAFChecker) initBypassTechniques() {
	// Cloudflare bypass techniques
	w.bypassTechs[Cloudflare] = []string{
		"Use HTTP/2 protocol to bypass some rule sets",
		"Try URL encoding special characters multiple times",
		"Add multiple X-Forwarded-For headers with varying values",
		"Use null byte injection in parameters",
		"Try different case variations in payloads",
	}

	// Incapsula bypass techniques
	w.bypassTechs[Incapsula] = []string{
		"Use HTTP parameter pollution",
		"Try adding fake parameters before actual payload",
		"Use alternative IP encoding formats",
		"Try payload fragmentation across multiple parameters",
		"Use different Content-Types to bypass inspection",
	}

	// Akamai bypass techniques
	w.bypassTechs[Akamai] = []string{
		"Try Unicode normalization evasion techniques",
		"Use HTTP method overriding",
		"Try payload obfuscation with HTML entities",
		"Add misleading Content-Type headers",
		"Use JSON/XML payload wrapping",
	}

	// AWS WAF bypass techniques
	w.bypassTechs[AWSWAFv2] = []string{
		"Try oversized payloads to bypass inspection",
		"Use wildcard content-types",
		"Try request body in unexpected parameters",
		"Use non-standard HTTP methods",
		"Try request splitting techniques",
	}

	// F5 BIG-IP bypass techniques
	w.bypassTechs[F5BigIP] = []string{
		"Try parameter name obfuscation",
		"Use uncommon HTTP headers to deliver payloads",
		"Try path normalization tricks",
		"Use alternate character sets and encodings",
		"Try HTTP request smuggling",
	}

	// Default bypass techniques for unknown WAFs
	w.bypassTechs[Unknown] = []string{
		"Try different payload encodings (URL, double URL, hex, unicode)",
		"Use HTTP header mutations",
		"Try changing the HTTP method (GET, POST, PUT, etc.)",
		"Add random parameters to the request",
		"Try using different Content-Type headers",
		"Use payload obfuscation techniques",
		"Try request timing variations",
	}

	// WAF-specific bypass techniques for additional WAFs
	w.bypassTechs[AWSWAFv2] = []string{
		"Try oversized payloads to bypass inspection",
		"Use wildcard content-types",
		"Try request body in unexpected parameters",
		"Use non-standard HTTP methods",
		"Try request splitting techniques",
		"Implement multi-stage payloads that assemble on the client side",
		"Use Unicode normalization evasion",
		"Try various JSON/XML payload obfuscation techniques",
	}

	w.bypassTechs[F5BigIP] = []string{
		"Try parameter name obfuscation",
		"Use uncommon HTTP headers to deliver payloads",
		"Try path normalization tricks",
		"Use alternate character sets and encodings",
		"Try HTTP request smuggling",
		"Implement payload chunking across multiple parameters",
		"Use HTTP/2 protocol features to bypass inspection",
	}

	w.bypassTechs[ModSecurity] = []string{
		"Use alternate character encodings",
		"Try evasion with NULL bytes",
		"Implement comment injection in payloads",
		"Use different case variations for keywords",
		"Try payload fragmentation across multiple parameters",
		"Use HTTP parameter pollution techniques",
		"Implement timing-based evasion techniques",
	}
}
