# 📝 Content Management Systems (CMS)

Content Management Systems power millions of websites worldwide. This section documents configuration files, plugin/theme locations, and security considerations for popular CMS platforms.

## Available Services

### Open Source CMS

- **[WordPress](wordpress.md)** - Most popular CMS platform
  - Powers 40%+ of websites
  - Extensive plugin ecosystem
  - PHP-based

- **[Drupal](drupal.md)** - Enterprise-grade CMS
  - Highly customizable
  - Strong security focus
  - Modular architecture

## Common Pentest Scenarios

### Initial Reconnaissance
- CMS version detection
- Plugin/theme enumeration
- Admin panel discovery

### Vulnerability Assessment
- Outdated core/plugins/themes
- Known CVE exploitation
- Configuration issues

### Common Attack Vectors
- SQL injection
- File upload vulnerabilities
- Authentication bypass
- Privilege escalation

## Quick Reference

| CMS | Default Admin | Config File | Common Paths |
|-----|---------------|-------------|--------------|
| WordPress | `/wp-admin/` | `wp-config.php` | `/wp-content/` |
| Drupal | `/admin/` | `settings.php` | `/sites/default/` |

## Security Best Practices

- Keep core and plugins updated
- Use strong admin credentials
- Disable file editing in admin panel
- Implement security plugins
- Regular backups
- Two-factor authentication
- Hide version information

## Contributing

Know another CMS that should be documented? [Contribute](../../CONTRIBUTING.md)!

---

# ==========================================
# docs/services/auth/index.md
# ==========================================

# 🔐 Authentication Services

Authentication services handle user access and identity management. This section covers configuration files, credential storage, and security considerations for common authentication protocols and services.

## Available Services

### Remote Access

- **[SSH (Secure Shell)](ssh.md)** - Secure remote access protocol
  - Encrypted communication
  - Key-based authentication
  - Port forwarding capabilities

- **[FTP (File Transfer Protocol)](ftp.md)** - File transfer service
  - Plain text protocol (insecure)
  - FTPS/SFTP secure alternatives
  - Anonymous access risks

## Common Pentest Scenarios

### Initial Access
- Weak credentials
- Default accounts
- Key exposure

### Brute Force Attacks
- Password spraying
- Credential stuffing
- Dictionary attacks

### Configuration Issues
- Weak encryption
- Outdated protocols
- Insecure permissions

## Quick Reference

| Service | Default Port | Config Location (Linux) | Key Locations |
|---------|--------------|-------------------------|---------------|
| SSH | 22 | `/etc/ssh/` | `~/.ssh/` |
| FTP | 21 | `/etc/vsftpd.conf` | `/etc/ftpusers` |

## Security Best Practices

- Disable password authentication (use keys)
- Change default ports
- Implement fail2ban/rate limiting
- Use strong encryption algorithms
- Regular audit of access logs
- Principle of least privilege
- Two-factor authentication

## Contributing

Know another authentication service that should be documented? [Contribute](../../CONTRIBUTING.md)!

---