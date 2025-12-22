# [Service Name]

!!! info "Information"
    **Category:** [Web Server | Database | CMS | Authentication | Cloud | etc.]  
    **Tags:** 'tag1' 'tag2' 'tag3'  
    **Criticality:** 🔴 High | 🟠 Medium | 🟡 Low

## Description

[Brief description of the service, its purpose, and common use cases. Include version information if relevant.]

---

## Configuration Files

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Main configuration
    /path/to/main/config.conf
    
    # Additional configs
    /path/to/additional/configs/
    ```

=== "Linux (RedHat/CentOS)"
    ```bash
    # Main configuration
    /path/to/main/config.conf
    ```

=== "Windows"
    ```powershell
    # Standard installation
    C:\Path\To\Config\file.conf
    ```

=== "macOS"
    ```bash
    # System installation
    /path/to/config.conf
    
    # Homebrew
    /usr/local/etc/service/config.conf
    /opt/homebrew/etc/service/config.conf
    ```

---

## Log Files

```bash
# Debian/Ubuntu
/var/log/service/access.log
/var/log/service/error.log

# RedHat/CentOS
/var/log/service/access_log
/var/log/service/error_log

# Windows
C:\Path\To\Logs\access.log
C:\Path\To\Logs\error.log
```

---

## Sensitive Files

!!! danger "Credentials and sensitive data"
    The following files may contain critical information:
    
    - `file1` - Description
    - `file2` - Description
    - `file3` - Description

!!! warning "Backup files"
    Don't forget to check for backups:
    
    - `*.conf~`
    - `*.conf.bak`
    - `*.conf.old`
    - `*.conf.backup`
    - `*.conf.save`

---

## Data Directories

```bash
# Debian/Ubuntu
/var/lib/service/
/var/data/service/

# RedHat/CentOS
/var/lib/service/

# Windows
C:\ProgramData\Service\

# macOS
/Library/Application Support/Service/
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    - How to identify the service version
    - Default ports to scan
    - Banner grabbing techniques

!!! tip "Enumeration"
    - Common misconfigurations to check
    - Default credentials to test
    - Information disclosure vulnerabilities

!!! tip "Exploitation"
    - Known attack vectors
    - Common vulnerabilities
    - Exploitation techniques

!!! tip "Post-Exploitation"
    - Where to find credentials
    - How to maintain access
    - Lateral movement opportunities

---

## Useful Commands

```bash
# Check if service is running
systemctl status service-name
ps aux | grep service

# Test configuration
service-name --test-config

# List modules/plugins
service-name --list-modules

# Locate configuration files
find / -name "service*.conf" 2>/dev/null
locate service.conf

# Search for credentials
grep -r "password" /etc/service/ 2>/dev/null

# Read logs in real-time
tail -f /var/log/service/access.log
tail -f /var/log/service/error.log
```

---

## Known Vulnerabilities

??? danger "CVE-YYYY-XXXXX - Vulnerability Name"
    Description of the vulnerability.
    
    **Affected versions:** X.X.X  
    **Exploit:**
    ```bash
    # Exploitation command or PoC
    ```

??? danger "CVE-YYYY-XXXXX - Another Vulnerability"
    Description of another vulnerability.
    
    **Affected versions:** X.X.X  
    **Exploit:**
    ```bash
    # Exploitation command or PoC
    ```

---

## Hardening

!!! success "Best practices"
    - Security recommendation 1
    - Security recommendation 2
    - Security recommendation 3
    - Keep the service regularly updated
    - Use strong authentication
    - Enable encryption where possible

---

## References

- [Official Documentation](https://example.com/docs)
- [OWASP Guidelines](https://owasp.org)
- [CVE List](https://cve.mitre.org)
- [Security Advisories](https://example.com/security)

---

## Exploitation Examples

??? example "Example 1: Common Attack"
    ```bash
    # Description of the attack
    command --with-options target
    
    # Expected output
    # Result explanation
    ```

??? example "Example 2: Another Attack"
    ```bash
    # Description of the attack
    command --with-options target
    ```

---

## Metadata

- **Template version:** 1.0
- **Last updated:** [Month Year]
- **Contributor:** [Your Name/Organization]
- **Sources verified:** [Yes/No]
