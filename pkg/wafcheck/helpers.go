package wafcheck

import (
	"strings"
)

// mapCDNCheckProviderToWAFType maps a cdncheck WAF provider string to our WAFType
func mapCDNCheckProviderToWAFType(provider string) WAFType {
	providerLower := strings.ToLower(provider)

	switch {
	case strings.Contains(providerLower, "cloudflare"):
		return Cloudflare
	case strings.Contains(providerLower, "incapsula") || strings.Contains(providerLower, "imperva"):
		return Incapsula
	case strings.Contains(providerLower, "akamai"):
		return Akamai
	case strings.Contains(providerLower, "aws") || strings.Contains(providerLower, "amazon"):
		return AWSWAFv2
	case strings.Contains(providerLower, "f5") || strings.Contains(providerLower, "big-ip"):
		return F5BigIP
	case strings.Contains(providerLower, "fortinet") || strings.Contains(providerLower, "fortiweb"):
		return Fortinet
	case strings.Contains(providerLower, "sucuri"):
		return Sucuri
	case strings.Contains(providerLower, "modsecurity") || strings.Contains(providerLower, "mod_security"):
		return ModSecurity
	case strings.Contains(providerLower, "wordfence"):
		return Wordfence
	case strings.Contains(providerLower, "barracuda"):
		return Barracuda
	case strings.Contains(providerLower, "fastly"):
		return Fastly
	case strings.Contains(providerLower, "radware"):
		return Radware
	case strings.Contains(providerLower, "dotdefender"):
		return DotDefender
	case strings.Contains(providerLower, "wallarm"):
		return Wallarm
	case strings.Contains(providerLower, "reblaze"):
		return Reblaze
	case strings.Contains(providerLower, "varnish"):
		return Varnish
	case strings.Contains(providerLower, "distil"):
		return Distil
	case strings.Contains(providerLower, "stackpath"):
		return Stackpath
	case strings.Contains(providerLower, "azure") || strings.Contains(providerLower, "front door"):
		return AzureFrontDoor
	case strings.Contains(providerLower, "google") || strings.Contains(providerLower, "cloud armor"):
		return GoogleCloud
	default:
		return Unknown
	}
}

// mapCDNProviderToWAFType maps a CDN provider to a potential WAF type
// Many CDNs also offer WAF capabilities
func mapCDNProviderToWAFType(provider string) WAFType {
	providerLower := strings.ToLower(provider)

	switch {
	case strings.Contains(providerLower, "cloudflare"):
		return Cloudflare
	case strings.Contains(providerLower, "akamai"):
		return Akamai
	case strings.Contains(providerLower, "fastly"):
		return Fastly
	case strings.Contains(providerLower, "sucuri"):
		return Sucuri
	case strings.Contains(providerLower, "incapsula") || strings.Contains(providerLower, "imperva"):
		return Incapsula
	case strings.Contains(providerLower, "stackpath"):
		return Stackpath
	case strings.Contains(providerLower, "azure") || strings.Contains(providerLower, "microsoft"):
		return AzureFrontDoor
	case strings.Contains(providerLower, "aws") || strings.Contains(providerLower, "amazon") || strings.Contains(providerLower, "cloudfront"):
		return AWSWAFv2
	case strings.Contains(providerLower, "google"):
		return GoogleCloud
	default:
		return Unknown
	}
}
