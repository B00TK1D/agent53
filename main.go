package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// Config represents the DNS server configuration
type Config struct {
	ListenAddr    string                  `yaml:"listen_addr"`
	LogQueries    bool                    `yaml:"log_queries"`
	LogFile       string                  `yaml:"log_file,omitempty"`
	Domains       map[string]DomainConfig `yaml:"domains"`
	RebindDomains []string                `yaml:"rebind_domains,omitempty"`
	TTL           int                     `yaml:"ttl,omitempty"`
	Upstream      UpstreamConfig          `yaml:"upstream,omitempty"`
}

// UpstreamConfig represents upstream DNS server configuration
type UpstreamConfig struct {
	Enabled bool     `yaml:"enabled"`
	Servers []string `yaml:"servers,omitempty"`
	Timeout int      `yaml:"timeout,omitempty"`
}

// DomainConfig represents configuration for a specific domain
type DomainConfig struct {
	DefaultIP string         `yaml:"default_ip"`
	Rules     []SourceIPRule `yaml:"rules,omitempty"`
}

// SourceIPRule represents a rule based on source IP or subnet
type SourceIPRule struct {
	SourceIP string `yaml:"source_ip"` // Can be IP or CIDR
	TargetIP string `yaml:"target_ip"`
}

// DNSHandler handles DNS requests
type DNSHandler struct {
	config   *Config
	logger   *log.Logger
	upstream *dns.Client
}

// NewDNSHandler creates a new DNS handler
func NewDNSHandler(config *Config) *DNSHandler {
	var logger *log.Logger
	if config.LogFile != "" {
		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("Warning: Could not open log file %s, using stdout: %v", config.LogFile, err)
			logger = log.New(os.Stdout, "", log.LstdFlags)
		} else {
			logger = log.New(file, "", log.LstdFlags)
		}
	} else {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	// Create upstream DNS client if enabled
	var upstream *dns.Client
	if config.Upstream.Enabled && len(config.Upstream.Servers) > 0 {
		upstream = &dns.Client{
			Net:     "udp",
			Timeout: time.Duration(config.Upstream.Timeout) * time.Second,
		}
		if upstream.Timeout == 0 {
			upstream.Timeout = 5 * time.Second // Default timeout
		}
	}

	return &DNSHandler{config: config, logger: logger, upstream: upstream}
}

// ServeDNS implements the dns.Handler interface
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := getClientIP(w)

	// Log the query if enabled
	if h.config.LogQueries {
		h.logger.Printf("DNS Query from %s: %s %s", clientIP, r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype])
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Handle A records
	if r.Question[0].Qtype == dns.TypeA {
		domain := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
		targetIP := h.getTargetIP(domain, clientIP)

		if targetIP != "" {
			ttl := h.config.TTL
			if ttl == 0 {
				ttl = 300 // Default 5 minutes
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s %d A %s", r.Question[0].Name, ttl, targetIP))
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		} else if h.upstream != nil {
			// Try upstream resolution
			upstreamMsg := h.queryUpstream(r)
			if upstreamMsg != nil {
				msg = upstreamMsg
			}
		}
	}

	// Handle AAAA records (IPv6)
	if r.Question[0].Qtype == dns.TypeAAAA {
		domain := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
		targetIP := h.getTargetIP(domain, clientIP)

		if targetIP != "" {
			// For IPv6, we'll return the IPv4 mapped to IPv6 or a default IPv6
			ipv6 := h.mapIPv4ToIPv6(targetIP)
			ttl := h.config.TTL
			if ttl == 0 {
				ttl = 300 // Default 5 minutes
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s %d AAAA %s", r.Question[0].Name, ttl, ipv6))
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		} else if h.upstream != nil {
			// Try upstream resolution
			upstreamMsg := h.queryUpstream(r)
			if upstreamMsg != nil {
				msg = upstreamMsg
			}
		}
	}

	// Handle other record types with upstream if no local configuration
	if len(msg.Answer) == 0 && h.upstream != nil {
		upstreamMsg := h.queryUpstream(r)
		if upstreamMsg != nil {
			msg = upstreamMsg
		}
	}

	w.WriteMsg(msg)
}

// getTargetIP determines the target IP based on domain and source IP
func (h *DNSHandler) getTargetIP(domain, sourceIP string) string {
	// Check if this is a rebind domain
	if h.isRebindDomain(domain) {
		return h.getRebindIP(domain, sourceIP)
	}

	// Check if we have configuration for this domain
	domainConfig, exists := h.config.Domains[domain]
	if !exists {
		return ""
	}

	// Check source IP rules first
	for _, rule := range domainConfig.Rules {
		if h.matchesSourceIP(sourceIP, rule.SourceIP) {
			return rule.TargetIP
		}
	}

	// Return default IP if no rules match
	return domainConfig.DefaultIP
}

// matchesSourceIP checks if the client IP matches the rule's source IP or subnet
func (h *DNSHandler) matchesSourceIP(clientIP, ruleSourceIP string) bool {
	// Direct IP match
	if clientIP == ruleSourceIP {
		return true
	}

	// CIDR match
	_, cidr, err := net.ParseCIDR(ruleSourceIP)
	if err == nil {
		clientAddr := net.ParseIP(clientIP)
		if clientAddr != nil && cidr.Contains(clientAddr) {
			return true
		}
	}

	return false
}

// isRebindDomain checks if a domain is configured for DNS rebinding
func (h *DNSHandler) isRebindDomain(domain string) bool {
	for _, rebindDomain := range h.config.RebindDomains {
		if strings.HasSuffix(domain, rebindDomain) {
			return true
		}
	}
	return false
}

// getRebindIP generates a rebind IP based on the domain and source IP
func (h *DNSHandler) getRebindIP(domain, sourceIP string) string {
	// For DNS rebinding, we can return different IPs based on various factors
	// This is a simple implementation that rotates between different IPs

	// Extract a hash from the domain and source IP for consistent rotation
	hash := 0
	for _, char := range domain + sourceIP {
		hash += int(char)
	}

	// Rotate between different IPs for rebinding
	rebindIPs := []string{
		"127.0.0.1",
		"0.0.0.0",
		"169.254.169.254", // AWS metadata service
		"10.0.0.1",
		"192.168.1.1",
	}

	index := hash % len(rebindIPs)
	return rebindIPs[index]
}

// queryUpstream queries upstream DNS servers
func (h *DNSHandler) queryUpstream(r *dns.Msg) *dns.Msg {
	if h.upstream == nil || len(h.config.Upstream.Servers) == 0 {
		return nil
	}

	// Try each upstream server
	for _, server := range h.config.Upstream.Servers {
		// Add port if not specified
		if !strings.Contains(server, ":") {
			server = server + ":53"
		}

		// Log upstream query
		if h.config.LogQueries {
			h.logger.Printf("Upstream DNS query to %s: %s %s", server, r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype])
		}

		// Query upstream server
		upstreamMsg, _, err := h.upstream.Exchange(r, server)
		if err != nil {
			h.logger.Printf("Upstream DNS error for %s: %v", server, err)
			continue
		}

		// Return successful response
		if upstreamMsg != nil && len(upstreamMsg.Answer) > 0 {
			return upstreamMsg
		}
	}

	return nil
}

// mapIPv4ToIPv6 maps an IPv4 address to IPv6 (simplified mapping)
func (h *DNSHandler) mapIPv4ToIPv6(ipv4 string) string {
	// Simple mapping: ::ffff:0:0/96 prefix
	ip := net.ParseIP(ipv4)
	if ip != nil {
		return fmt.Sprintf("::ffff:%s", ipv4)
	}
	return "::1" // fallback to localhost
}

// getClientIP extracts the client IP from the DNS response writer
func getClientIP(w dns.ResponseWriter) string {
	if udpConn, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		return udpConn.IP.String()
	}
	if tcpConn, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return tcpConn.IP.String()
	}
	return "unknown"
}

// loadConfig loads configuration from a YAML file
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Set defaults
	if config.ListenAddr == "" {
		config.ListenAddr = ":53"
	}

	return &config, nil
}

func main() {
	// Parse command line arguments
	var (
		configFile = flag.String("config", "config.yaml", "Configuration file path")
		version    = flag.Bool("version", false, "Show version information")
		help       = flag.Bool("help", false, "Show help information")
	)
	flag.Parse()

	if *help {
		fmt.Println("Agent53 - Custom DNS Server")
		fmt.Println("Usage: agent53 [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Println("  agent53 -config /path/to/config.yaml")
		os.Exit(0)
	}

	if *version {
		fmt.Println("Agent53 v1.0.0 - Custom DNS Server")
		os.Exit(0)
	}

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Create DNS handler
	handler := NewDNSHandler(config)

	// Create DNS server
	server := &dns.Server{
		Addr:    config.ListenAddr,
		Net:     "udp",
		Handler: handler,
	}

	// Start server
	log.Printf("Starting DNS server on %s", config.ListenAddr)
	log.Printf("Configuration loaded from %s", configFile)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
