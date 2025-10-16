# Agent53 - Custom DNS Server

Agent53 is a custom Go DNS server designed for DNS rebinding attacks, source IP-based routing, and comprehensive DNS query logging. It allows you to configure different DNS responses based on the source IP address or subnet of the requesting client.

## Features

- **Source IP-based Routing**: Return different IP addresses based on the client's source IP or subnet
- **DNS Rebinding Support**: Configure domains for DNS rebinding attacks
- **Comprehensive Logging**: Log all DNS queries with source IP information
- **Flexible Configuration**: YAML-based configuration with support for CIDR notation
- **IPv4 and IPv6 Support**: Handle both A and AAAA record queries
- **TTL Configuration**: Customizable TTL values for DNS responses
- **Upstream DNS Resolution**: Forward unconfigured domains to upstream DNS servers

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd agent53
```

2. Install dependencies:
```bash
go mod tidy
```

3. Build the server:
```bash
go build -o agent53 main.go
```

## Usage

### Basic Usage

```bash
# Run with default config.yaml
./agent53

# Run with custom config file
./agent53 -config /path/to/config.yaml

# Show help
./agent53 -help

# Show version
./agent53 -version
```

### Configuration

The server uses a YAML configuration file. Here's an example:

```yaml
# Agent53 DNS Server Configuration
listen_addr: ":53"
log_queries: true
log_file: "dns-server.log"
ttl: 60

# Upstream DNS configuration
upstream:
  enabled: true
  servers:
    - "8.8.8.8"
    - "1.1.1.1"
  timeout: 5

# Domains configured for DNS rebinding
rebind_domains:
  - "rebind.test"
  - "evil.local"

# Domain configurations
domains:
  test.local:
    default_ip: "127.0.0.1"
    rules:
      - source_ip: "192.168.1.0/24"
        target_ip: "192.168.1.100"
      - source_ip: "10.0.0.0/8"
        target_ip: "10.0.0.1"

  malware.test:
    default_ip: "127.0.0.1"
    rules:
      - source_ip: "192.168.1.50"
        target_ip: "192.168.1.200"
```

### Configuration Options

- `listen_addr`: Address and port to listen on (default: ":53")
- `log_queries`: Enable/disable query logging (default: true)
- `log_file`: Path to log file (optional, defaults to stdout)
- `ttl`: TTL value for DNS responses in seconds (default: 300)
- `upstream`: Upstream DNS configuration
  - `enabled`: Enable/disable upstream DNS resolution (default: false)
  - `servers`: List of upstream DNS servers (e.g., ["8.8.8.8", "1.1.1.1"])
  - `timeout`: Timeout for upstream queries in seconds (default: 5)
- `rebind_domains`: Array of domain suffixes that should use DNS rebinding
- `domains`: Map of domain configurations

### Domain Configuration

Each domain can have:
- `default_ip`: Default IP to return if no rules match
- `rules`: Array of source IP-based rules

### Source IP Rules

Rules support:
- **Exact IP match**: `"192.168.1.50"`
- **CIDR notation**: `"192.168.1.0/24"`, `"10.0.0.0/8"`
- `target_ip`: IP address to return for matching clients

## DNS Rebinding

DNS rebinding domains are configured in the `rebind_domains` array. For these domains, the server will rotate between different IP addresses to facilitate DNS rebinding attacks.

## Upstream DNS Resolution

When upstream DNS is enabled, the server will forward queries for unconfigured domains to the specified upstream DNS servers. This allows the server to act as a hybrid DNS server that can:

- Serve custom responses for configured domains
- Forward unconfigured domains to upstream servers (like Google DNS, Cloudflare, etc.)
- Provide fallback resolution for any domain not explicitly configured

### Upstream Configuration

```yaml
upstream:
  enabled: true
  servers:
    - "8.8.8.8"      # Google DNS
    - "1.1.1.1"      # Cloudflare DNS
    - "208.67.222.222" # OpenDNS
  timeout: 5
```

### Behavior

1. **Configured domains**: Return custom responses based on source IP rules
2. **Unconfigured domains**: Forward to upstream DNS servers
3. **Upstream failure**: Return NXDOMAIN if all upstream servers fail
4. **Logging**: All upstream queries are logged with server information

## Examples

### Testing DNS Resolution

```bash
# Test with dig
dig @127.0.0.1 test.local

# Test from specific source (requires root)
dig @127.0.0.1 -b 192.168.1.50 malware.test
```

### Logging

The server logs all DNS queries with:
- Source IP address
- Query type (A, AAAA, etc.)
- Domain name
- Timestamp

Example log entry:
```
2024-01-15 10:30:45 DNS Query from 192.168.1.50: malware.test A
```


## Building and Distribution

```bash
# Build for current platform
go build -o agent53 main.go

# Build for Linux (from macOS/Windows)
GOOS=linux GOARCH=amd64 go build -o agent53-linux main.go

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o agent53.exe main.go
```