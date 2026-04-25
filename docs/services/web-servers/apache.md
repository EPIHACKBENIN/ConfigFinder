# Apache HTTP Server

!!! info "Information"
    **Category:** Web Server  
    **Tags:** 'web' 'http' 'apache'  
    **Criticality:** 🔴 High

## Description

Apache HTTP Server is a free and open-source cross-platform web server software. It is one of the most widely used web servers globally. Identifying its configuration files during a pentest is critical for discovering virtual hosts, finding hidden directories, and identifying misconfigurations like enabled directory listing or server status pages.

---

## Configuration Files

=== "Linux (Debian/Ubuntu/Kali)"
    ```bash
    # Main configuration
    /etc/apache2/apache2.conf
    
    # Ports and Virtual Hosts
    /etc/apache2/ports.conf
    /etc/apache2/sites-available/
    /etc/apache2/sites-enabled/
    
    # Modules and generic configs
    /etc/apache2/mods-enabled/
    /etc/apache2/conf-enabled/
    ```

=== "Linux (RedHat/CentOS/Fedora)"
    ```bash
    # Main configuration
    /etc/httpd/conf/httpd.conf
    
    # Additional configurations
    /etc/httpd/conf.d/
    /etc/httpd/conf.modules.d/
    ```

=== "Windows"
    ```powershell
    # Standalone installation
    C:\Program Files\Apache Group\Apache2\conf\httpd.conf
    C:\Apache24\conf\httpd.conf
    
    # XAMPP
    C:\xampp\apache\conf\httpd.conf
    C:\xampp\apache\conf\extra\httpd-vhosts.conf
    
    # WAMP
    C:\wamp64\bin\apache\apache[version]\conf\httpd.conf
    ```

=== "macOS"
    ```bash
    # System installation
    /etc/apache2/httpd.conf
    /private/etc/apache2/httpd.conf
    
    # Homebrew
    /usr/local/etc/httpd/httpd.conf # Intel
    /opt/homebrew/etc/httpd/httpd.conf # Apple Silicon
    ```

---

## Log Files

```bash
# Debian/Ubuntu
/var/log/apache2/access.log
/var/log/apache2/error.log

# RedHat/CentOS
/var/log/httpd/access_log
/var/log/httpd/error_log

# Windows (XAMPP example)
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log

# macOS
/var/log/apache2/access_log
/var/log/apache2/error_log
```

---

## Sensitive Files

!!! danger "Credentials and sensitive data"
    The following files may contain critical information:
    
    - `.htaccess` - Per-directory configuration file, can override main config
    - `.htpasswd` - Stores usernames and passwords for Basic Authentication
    - `/etc/apache2/envvars` - Environment variables, might contain sensitive data

!!! warning "Backup files"
    Don't forget to check for backups:
    
    - `httpd.conf.bak`
    - `apache2.conf.old`
    - `*.conf.save`

---

## Data Directories

```bash
# Default Web Root (Debian/Ubuntu)
/var/www/html/

# Default Web Root (RedHat/CentOS)
/var/www/html/

# XAMPP / WAMP Default
C:\xampp\htdocs\
C:\wamp64\www\

# macOS Default
/Library/WebServer/Documents/
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    - **Identify Version**: Check HTTP response headers (`Server: Apache/2.4.41`) or default error pages.
    - **Server Status**: Check if `mod_status` is enabled by navigating to `/server-status` or `/server-info`.

!!! tip "Enumeration"
    - Look for exposed `.htaccess` files which can reveal internal paths and configurations.
    - Search configuration files for `Require all granted`, `Options +Indexes` (directory listing enabled), or alias/proxy configurations.

!!! tip "Exploitation"
    - Exploit LFI (Local File Inclusion) to read `/etc/apache2/apache2.conf` or `/etc/apache2/sites-enabled/000-default.conf` to discover other internal endpoints.
    - Read `.htpasswd` files via LFI and crack them using John the Ripper or Hashcat.

---

## Useful Commands

```bash
# Check if service is running
systemctl status apache2   # Debian/Ubuntu
systemctl status httpd     # RHEL/CentOS

# Test configuration syntax
apache2ctl configtest
apachectl -t

# Display virtual hosts
apache2ctl -S
httpd -S

# Display compiled modules
apache2ctl -M

# Find all .htaccess files
find /var/www/ -name ".htaccess"

# Read real-time access logs
tail -f /var/log/apache2/access.log
```

---

## Hardening

!!! success "Best practices"
    - Disable directory listing (`Options -Indexes`).
    - Hide server version by setting `ServerTokens Prod` and `ServerSignature Off`.
    - Disable unnecessary modules to reduce the attack surface.
    - Restrict access to `/server-status`.
    - Run Apache as a non-privileged user (e.g., `www-data`).

---

## Metadata

- **Template version:** 1.0
- **Last updated:** 2026-04
- **Contributor:** AI Assistant
- **Sources verified:** Yes
