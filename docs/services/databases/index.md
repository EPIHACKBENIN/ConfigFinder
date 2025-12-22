# 🗄️ Databases

Database management systems store and manage critical data. This section covers configuration files, credential locations, and security considerations for popular database systems.

## Available Services

### Relational Databases

- **[MySQL / MariaDB](mysql.md)** - Most popular open-source relational database
  - Wide adoption
  - LAMP stack component
  - Community and enterprise versions

- **[PostgreSQL](postgresql.md)** - Advanced open-source relational database
  - ACID compliance
  - Extensible architecture
  - Strong data integrity

### NoSQL Databases

- **[MongoDB](mongodb.md)** - Document-oriented NoSQL database
  - JSON-like documents
  - Horizontal scaling
  - Flexible schema

- **[Redis](redis.md)** - In-memory data structure store
  - Key-value store
  - Caching and session management
  - Pub/Sub messaging

## Common Pentest Scenarios

### Initial Access
- Default credentials
- Weak authentication
- Network exposure without authentication

### Enumeration
- Database listing
- User enumeration
- Permission analysis

### Data Extraction
- SQL injection
- NoSQL injection
- Backup file discovery

## Quick Reference

| Database | Default Port | Config Location (Linux) | Default User |
|----------|--------------|-------------------------|--------------|
| MySQL | 3306 | `/etc/mysql/` | root |
| PostgreSQL | 5432 | `/etc/postgresql/` | postgres |
| MongoDB | 27017 | `/etc/mongod.conf` | admin |
| Redis | 6379 | `/etc/redis/redis.conf` | - |

## Security Best Practices

- Never use default credentials
- Disable remote root access
- Use encrypted connections (TLS/SSL)
- Regular security updates
- Proper access control configuration
- Audit logging enabled

## Contributing

Know another database that should be documented? [Contribute](../../CONTRIBUTING.md)!

---
