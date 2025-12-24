# Redis

!!! info "Information"
    **Category:** Database  
    **Tags:** 'database' 'cache' 'nosql' 'redis' 'memory'  
    **Criticality:** 🔴 High

## Description

Redis is an open-source, in-memory data structure store used as a database, cache, and message broker. It supports various data structures such as strings, hashes, lists, sets, and sorted sets. Redis is widely used for performance-critical applications but is often misconfigured, making it a common target during pentests.

## How it works

- **In-memory storage:** Data is primarily stored in RAM, enabling extremely fast read/write operations.
- **Client-server model:** Clients communicate with the Redis server over TCP (default port 6379).
- **Persistence (optional):** Data can be saved to disk using RDB snapshots or AOF logs.
- **Authentication (optional):** Redis can be configured with a password, but authentication is disabled by default in many setups.

---

## Configuration Files

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Main Redis configuration file
    /etc/redis/redis.conf

    # Additional configuration directory (if used)
    /etc/redis/conf.d/
    ```

=== "Linux (RedHat/CentOS)"
    ```bash
    # Main Redis configuration file
    /etc/redis/redis.conf

    # Alternative installation paths
    /etc/redis.conf
    ```

=== "Windows"
    ```powershell
    # Redis configuration file (Microsoft port / third-party builds)
    C:\Program Files\Redis\redis.windows.conf
    C:\Redis\redis.conf
    ```

=== "macOS"
    ```bash
    # Redis installed via Homebrew
    /usr/local/etc/redis.conf

    # Apple Silicon Homebrew path
    /opt/homebrew/etc/redis.conf
    ```

---

## Log Files

```bash
# Debian/Ubuntu
/var/log/redis/redis-server.log

# RedHat/CentOS
/var/log/redis/redis.log
/var/log/messages

# Windows
C:\Program Files\Redis\log\redis.log

# macOS (Homebrew)
/usr/local/var/log/redis.log
/opt/homebrew/var/log/redis.log
```

## Credentials

!!! info "Authentication"
    - Redis does not enforce authentication by default.
    - Password authentication is configured using the `requirepass` directive in `redis.conf`.
    - ACL-based authentication is available in Redis 6.0+ via the `users.acl` file.

```bash
# Example authentication directive
requirepass StrongPasswordHere
```

## Pentest Tips

!!! tip "Reconnaissance"
    - Scan port 6379 (default Redis port).
    - Identify Redis version via banner grabbing.

!!! tip "Misconfiguration Checks"
    - Check for unauthenticated access.
    - Verify if `protected-mode` is disabled.
    - Check bind address (`bind 0.0.0.0`) allowing external access.

!!! tip "Exploitation"
    - Write arbitrary files if Redis runs as root and filesystem permissions allow.
    - Abuse `CONFIG SET dir` and `dbfilename` to write SSH keys or cron jobs.
    - Dump in-memory sensitive data (sessions, tokens, credentials).

!!! tip "Post-Exploitation"
    - Extract application secrets stored in Redis.
    - Use Redis as a pivot point for lateral movement.
    - Persist access via modified configuration or scheduled tasks.


## Useful Commands

```bash
# Check if Redis is reachable
redis-cli -h [target_IP] -p 6379 ping

# Connect to Redis without authentication
redis-cli -h [target_IP] -p 6379

# Authenticate (if password is set)
AUTH <password>

# Get Redis server info
INFO

# List all keys (can be dangerous on production)
KEYS *

# Dump configuration
CONFIG GET *
```

## Known Vulnerabilities

??? danger "CVE-2022-0543 - Remote Code Execution (Lua Sandbox Escape)"
    Affects Debian-based Redis packages due to a misconfigured Lua sandbox, allowing arbitrary code execution.

---

## Metadata

- **Template version:** 1.0  
- **Last updated:** December 2025  
- **Contributor:** EpiHack Benin  
- **Sources verified:** Yes
