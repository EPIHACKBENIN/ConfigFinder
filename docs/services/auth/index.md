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