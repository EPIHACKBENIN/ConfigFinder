# File Transfer Protocol (FTP)

!!! info "Information"
    **Category:** Network protocol    
    **Tags:** 'file' 'auth' 'network' 'ftp'  
    **Criticality:** 🔴 High

## Description

File Transfer Protocol is a standard network protocol used to transfer files between a client and a server on a network like the internet. It allows users to upload files to a server, download files from a server, and manage files on remote computers. This is often used for website maintenance, data sharing, and transferring large amounts of data. 

## How it works

- **Client-server model:** FTP operates on a client-server architecture, where a user's computer (the client) connects to another computer (the server) to exchange files.
- **Two connections:** An FTP connection establishes two separate connections—one for control commands and another for the actual file data transfer.
- **Authentication:** Users typically need to authenticate with a username and password to access files, although some servers may allow anonymous access. 

---

## Configuration Files

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Main configuration for vsftpd (Very Secure FTP Daemon)
    /etc/vsftpd.conf

    # Main configuration for ProFTPD
    /etc/proftpd/proftpd.conf

    # Main modular configuration for ProFTPD
    /etc/proftpd/conf.d/

    # Main configuration for pure-ftpd
    /etc/pure-ftpd/conf/

    # User lists for vsftpd
    /etc/vsftpd.userlist
    /etc/vsftpd/ftpusers
    /etc/vsftpd.chroot_list
    ```

=== "Linux (RedHat/CentOS)"
    ```bash
    # Main configuration for vsftpd (Very Secure FTP Daemon)
    /etc/vsftpd/vsftpd.conf

    # Main configuration for ProFTPD
    /etc/proftpd.conf
    # or
    /usr/local/etc/proftpd.conf

    # User lists for vsftpd
    /etc/vsftpd/ftpusers
    /etc/vsftpd/user_list
    ```

=== "Windows"
    ```powershell
    # Main Configuration File
    %SystemRoot%\System32\inetsrv\config\ApplicationHost.config

    # Default physical location for an FTP site's files
    C:\inetpub\ftproot

    # Third-Party FTP Servers
    ## FilleZilla Server configuration files
    C:\Users\<username>\AppData\Local\filezilla-server

    ## Xlight FTP Server configuration files
    C:\Program Files\Xlight FTP Server\ftpd.hosts
    C:\Program Files\Xlight FTP Server\ftpd.option
    C:\Program Files\Xlight FTP Server\ftpd.password
    C:\Program Files\Xlight FTP Server\ftpd.rules
    C:\Program Files\Xlight FTP Server\ftpd.users
    ```

=== "macOS"
    ```bash
    # Older mac versions (pre-High Sierra) FTP managed by **launchd** service file
    /System/Library/LaunchDaemons/ftp.plist

    # Third-Party FTP Servers on macOS configuration files
    ## Pure-FTPd managed via Homebrew
    /usr/local/etc/pure-ftpd.conf

    ## VSFTPD managed via Homebrew
    /usr/local/etc/vsftpd.conf

    ## FilleZilla Server managed via a dedicated graphical interface
    %LOCALAPPDATA%\filezilla-server

    ## App Store "FTP Server" Apps managed via its graphical interface
    ~/Library/Containers/
    ```

---

## Log Files

```bash
# Debian/Ubuntu (vsftpd)
/var/log/vsftpd.log

# Debian/Ubuntu (ProFTPD)
/var/log/proftpd/proftpd.log

# Debian/Ubuntu (Pure-FTPd)
/var/log/pureftpd.log
/var/log/xferlog

# Debian/Ubuntu (Generic/System)
/var/log/xferlog
/var/log/messages
/var/log/auth.log

# RedHat/CentOS (vsftpd)
/var/log/messages
/var/log/secure
/var/log/xferlog
/var/log/vsftpd.log

# RedHat/CentOS (ProFTPD)
/var/log/proftpd/proftpd.log

# RedHat/CentOS (Pure-FTPd)
/var/log/pureftpd.log
/var/log/xferlog

# RedHat/CentOS (SFTP (SSH))
/var/log/secure

# Windows
C:\inetpub\logs\LogFiles\FTPSVCn\u_exYYMMDD.log
C:\Program Files\FileZilla Server\logs

# macOS
## Older macOS versions
/var/log/ftp.log
## GUI app
~/Library/Containers/net.langui.FTPServer/Data/Logs/
## Command-line installations
/var/log/xferlog
/var/log/secure
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    - Scan ports: 21 (Control Connection) 20 (Data Connection (Active Mode))

!!! tip "Exploitation"
    - Connect as Anonymous without password

!!! tip "Post-Exploitation"
    - Harvest credentials from configuration files or logs for lateral movement.
    - Upload web shells or malicious scripts to gain persistent access or escalate privileges.
    - Use discovered credentials to access other network services or systems.
    - Exfiltrate sensitive data stored on the FTP server.
    - Leverage FTP for pivoting to internal networks or as a staging point for further attacks.

---

## Useful Commands

```bash
# Manual Interaction
ftp [target_IP]

# Service Version and OS Fingerprinting
nmap -p 21 -sV --script=ftp-anon,ftp-banner [target_IP]

# Anonymous Access Check
nmap -p 21 --script=ftp-anon [target_IP]

# Vulnerability Scanning
nmap -p 21 --script=ftp-vuln-* [target_IP]

# FTP Bounce Attack Check
nmap -p 21 --script=ftp-bounce [target_IP]
```

---

## Known Vulnerabilities

??? danger "CVE-2025-47812 - Remote Code Execution"

---

## Metadata

- **Template version:** 1.0
- **Last updated:** November 2024
- **Contributor:** EpiHack Benin
- **Sources verified:** Yes