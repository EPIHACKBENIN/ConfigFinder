# 🌐 Web Servers

Web servers and reverse proxies are essential components of web infrastructure. This section documents configuration files, logs, and security considerations for common web server software.

## Available Services

### Production Web Servers

- **[Apache HTTP Server](apache.md)** - The world's most popular web server
  - Multi-platform support
  - Highly modular architecture
  - Extensive documentation

- **[Nginx](nginx.md)** - High-performance web server and reverse proxy
  - Event-driven architecture
  - Low memory footprint
  - Popular for high-traffic sites

- **[IIS (Internet Information Services)](iis.md)** - Microsoft's web server
  - Windows native integration
  - .NET framework support
  - Enterprise features

## Common Pentest Scenarios

### Initial Reconnaissance
- Version detection via HTTP headers
- Service fingerprinting
- Port scanning (80, 443, 8080, 8443)

### Configuration Analysis
- Default file locations
- Virtual host enumeration
- Module/plugin detection

### Common Vulnerabilities
- Directory traversal
- Information disclosure
- Misconfigured access controls
- Outdated software versions

## Quick Reference

| Server | Default HTTP | Default HTTPS | Config Location (Linux) |
|--------|--------------|---------------|-------------------------|
| Apache | 80 | 443 | `/etc/apache2/` or `/etc/httpd/` |
| Nginx | 80 | 443 | `/etc/nginx/` |
| IIS | 80 | 443 | `C:\inetpub\` |

## Contributing

Know another web server that should be documented? [Contribute](../../CONTRIBUTING.md)!

---
