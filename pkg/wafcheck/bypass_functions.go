package wafcheck

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// createPathMutationRequest creates a request with path mutations for WAF bypass
func (b *WAFBypasser) createPathMutationRequest(targetURL string, payload string) (*http.Request, error) {
	// Select a random path mutation
	mutationIndex := b.rnd.Intn(len(PathMutations))
	
	// Apply the mutation to the URL
	mutatedURL, err := MutateURL(targetURL, mutationIndex)
	if err != nil {
		return nil, err
	}
	
	// Parse the mutated URL
	parsedURL, err := url.Parse(mutatedURL)
	if err != nil {
		return nil, err
	}
	
	// Add the payload as a parameter
	q := parsedURL.Query()
	q.Add("param", payload)
	parsedURL.RawQuery = q.Encode()
	
	// Create the request
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

// createRandomUserAgentRequest creates a request with a random user agent
func (b *WAFBypasser) createRandomUserAgentRequest(targetURL string, payload string) (*http.Request, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	// Add the payload as a parameter
	q := parsedURL.Query()
	q.Add("param", payload)
	parsedURL.RawQuery = q.Encode()
	
	// Create the request
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	
	// Set a random user agent
	req.Header.Set("User-Agent", GetRandomUserAgent())
	
	return req, nil
}

// attemptPathMutationBypass tries to bypass a WAF using path mutations
func (b *WAFBypasser) attemptPathMutationBypass(targetURL string, payload string) ([]*BypassResult, error) {
	var results []*BypassResult
	
	// Generate all possible path mutations
	mutatedURLs, err := GenerateWAFBypassURLs(targetURL)
	if err != nil {
		return nil, err
	}
	
	// Try each mutation
	for i, mutatedURL := range mutatedURLs {
		// Limit the number of attempts to avoid excessive requests
		if i >= 20 {
			break
		}
		
		// Create a request with the mutated URL
		parsedURL, err := url.Parse(mutatedURL)
		if err != nil {
			continue
		}
		
		// Add the payload as a parameter
		q := parsedURL.Query()
		q.Add("param", payload)
		parsedURL.RawQuery = q.Encode()
		
		// Create the request
		req, err := http.NewRequest("GET", parsedURL.String(), nil)
		if err != nil {
			continue
		}
		
		// Use random user agent if enabled
		if b.useRandomUserAgent {
			req.Header.Set("User-Agent", GetRandomUserAgent())
		} else {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		}
		
		// Execute the request
		resp, err := b.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		
		// Determine if the bypass was successful
		success := resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 429 && resp.StatusCode != 503
		
		// Create the result
		result := &BypassResult{
			Technique:      PathMutation,
			Success:        success,
			StatusCode:     resp.StatusCode,
			ResponseLength: len(body),
			Request:        req,
			Response:       resp,
			Notes:          fmt.Sprintf("Attempted path mutation bypass with URL: %s", mutatedURL),
		}
		
		results = append(results, result)
		
		// If we found a successful bypass, return immediately
		if success {
			break
		}
	}
	
	return results, nil
}
