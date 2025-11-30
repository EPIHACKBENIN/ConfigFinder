# 📝 Content Management Systems (CMS)

Content Management Systems power millions of websites worldwide. This section documents configuration files, plugin/theme locations, and security considerations for popular CMS platforms.

## Available Services

### Open Source CMS

- **[WordPress](wordpress.md)** - Most popular CMS platform
  - Powers 40%+ of websites
  - Extensive plugin ecosystem
  - PHP-based

- **[Drupal](drupal.md)** - Enterprise-grade CMS
  - Highly customizable
  - Strong security focus
  - Modular architecture

## Common Pentest Scenarios

### Initial Reconnaissance
- CMS version detection
- Plugin/theme enumeration
- Admin panel discovery

### Vulnerability Assessment
- Outdated core/plugins/themes
- Known CVE exploitation
- Configuration issues

### Common Attack Vectors
- SQL injection
- File upload vulnerabilities
- Authentication bypass
- Privilege escalation

## Quick Reference

| CMS | Default Admin | Config File | Common Paths |
|-----|---------------|-------------|--------------|
| WordPress | `/wp-admin/` | `wp-config.php` | `/wp-content/` |
| Drupal | `/admin/` | `settings.php` | `/sites/default/` |

## Security Best Practices

- Keep core and plugins updated
- Use strong admin credentials
- Disable file editing in admin panel
- Implement security plugins
- Regular backups
- Two-factor authentication
- Hide version information

## Contributing

Know another CMS that should be documented? [Contribute](../../CONTRIBUTING.md)!

---