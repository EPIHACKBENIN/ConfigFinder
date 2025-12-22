# 🔍 ConfigFinder

> **Le GTFOBins des fichiers de configuration**  
> Référence rapide des fichiers de configuration sensibles pour pentesters et professionnels de la sécurité

[![MkDocs](https://img.shields.io/badge/Built%20with-MkDocs-blue)](https://www.mkdocs.org/)
[![Material](https://img.shields.io/badge/Theme-Material-cyan)](https://squidfunk.github.io/mkdocs-material/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 Pourquoi ConfigFinder ?

Lors d'un pentest ou d'une reconnaissance, identifier les fichiers de configuration critiques est essentiel mais chronophage. ConfigFinder centralise cette information pour **gagner du temps** et **améliorer l'efficacité**.

**Exemple d'usage :**
```
🔎 Service découvert : Apache HTTP Server
⚡ Recherche sur ConfigFinder
✅ Résultat instantané :
   - /etc/apache2/apache2.conf
   - /etc/apache2/sites-enabled/
   - /var/log/apache2/access.log
   - .htaccess, .htpasswd
```

## ✨ Fonctionnalités

- 🔍 **Recherche instantanée** : Trouve rapidement les fichiers par nom de service
- 📂 **Navigation par catégories** : Web, Database, Auth, CMS, etc.
- 🖥️ **Multi-OS** : Chemins pour Linux, Windows, macOS
- 🎯 **Informations ciblées** : Configs, logs, credentials, tips pentest
- 🌙 **Mode sombre** : Interface agréable pour les longues sessions
- 📱 **Responsive** : Fonctionne sur mobile et desktop

## 🚀 Accéder au site

👉 **[configfinder.github.io](https://epihack.github.io/configfinder/)**

## 🤝 Contribuer

ConfigFinder est un projet **open source et communautaire**. Toute contribution est la bienvenue !

### Comment ajouter un service ?

1. **Fork** ce repo
2. Crée un fichier dans `docs/services/[categorie]/[service].md`
3. Utilise le [template fourni](docs/services/TEMPLATE.md)
4. Teste en local avec `mkdocs serve`
5. Ouvre une **Pull Request**

📖 **[Guide complet de contribution](CONTRIBUTING.md)**

### Développement local

```bash
# Cloner le repo
git clone https://github.com/epihack/configfinder.git
cd configfinder

# Installer MkDocs
pip install -r requirements.txt

# Lancer le serveur local
mkdocs serve

# Accéder à http://127.0.0.1:8000
```

## 📊 Progression

- [x] Infrastructure MkDocs + Material
- [x] Template de documentation
- [x] 10 premiers services (MVP)
- [ ] 50 services
- [ ] 100 services
- [ ] 200+ services

**Services actuels :** `10 services (MVP atteint ✅)`

## 🎯 Public Cible

- Pentesters et consultants en sécurité
- Équipes Red Team
- Étudiants en cybersécurité
- Administrateurs système
- Chercheurs en sécurité

## 📚 Inspiration

ConfigFinder s'inspire de projets communautaires reconnus :
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## 📞 Contact

- **Créateur :** EPIHACK 
- **Organisation :** [EpiHack Bénin](https://github.com/epihack)
- **Email :** epihack.benin@gmail.com

## 📜 Licence

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">
  <p><strong>⭐ Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !</strong></p>
  <p>Fait avec ❤️ par la communauté cybersec</p>
</div>