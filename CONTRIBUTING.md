# Contributing to ConfigFinder

First off, thank you for considering contributing to ConfigFinder! 🎉

ConfigFinder is a community-driven project that aims to be the GTFOBins of configuration files. Every contribution helps pentesters and security professionals work more efficiently.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Adding a New Service](#adding-a-new-service)
- [Improving Existing Documentation](#improving-existing-documentation)
- [Style Guide](#style-guide)
- [Submission Process](#submission-process)

## 🤝 Code of Conduct

This project and everyone participating in it is governed by respect and professionalism. Please be kind and constructive in your interactions.

## 💡 How Can I Contribute?

### Reporting Issues

- Check if the issue already exists
- Use a clear and descriptive title
- Provide as much detail as possible
- Include examples if applicable

### Suggesting Enhancements

- Use a clear and descriptive title
- Explain why this enhancement would be useful
- Provide examples of how it would work

### Adding New Services

This is the most valuable contribution! See the detailed guide below.

## 📝 Adding a New Service

### Step 1: Choose a Service

Priority services to document:
- Popular web servers, databases, CMS
- Common authentication services
- Cloud platforms and their services
- Container and orchestration tools
- Any service commonly encountered in pentests

### Step 2: Create the Documentation File

1. **Fork the repository**
   ```bash
   git clone https://github.com/EPIHACKBENIN/ConfigFinder.git
   cd ConfigFinder
   ```

2. **Create a new branch**
   ```bash
   git checkout -b add-service-name
   ```

3. **Create the service file**
   - Navigate to the appropriate category in `docs/services/`
   - If the category doesn't exist, create it
   - Copy the template: `docs/services/TEMPLATE.md`
   - Name your file: `service-name.md` (lowercase, hyphens for spaces)

4. **Fill in the template**
   - Use the template structure as a guide
   - Include all relevant sections
   - Verify all paths and commands
   - Add real-world examples

### Step 3: Update Navigation

Edit `mkdocs.yml` to add your service to the navigation:

```yaml
nav:
  - Services:
      - Your Category:
          - services/category/index.md
          - Your Service: services/category/your-service.md
```

### Step 4: Test Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run local server
mkdocs serve

# Open http://127.0.0.1:8000
# Verify your documentation renders correctly
```

### Step 5: Submit Pull Request

1. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add [Service Name] documentation"
   git push origin add-service-name
   ```

2. **Create Pull Request**
   - Go to GitHub and create a PR
   - Use a clear title: "Add [Service Name] documentation"
   - Describe what you've added
   - Reference any related issues

## 🔄 Improving Existing Documentation

Found an error or want to add information to existing docs?

1. Fork and create a branch
2. Make your changes
3. Test locally
4. Submit a PR with a clear description

## 📐 Style Guide

### Markdown Formatting

- Use ATX-style headers (`#` not `===`)
- Use fenced code blocks with language specification
- Use admonitions for important information:
  - `!!! info` for general information
  - `!!! tip` for helpful tips
  - `!!! warning` for warnings
  - `!!! danger` for critical security information
  - `??? example` for collapsible examples

### Content Guidelines

#### File Paths
- Always provide multi-OS paths when applicable
- Use tabs for different OS (Debian/Ubuntu, RedHat/CentOS, Windows, macOS)
- Include common installation locations (standard, XAMPP, Homebrew, etc.)

#### Commands
- Test all commands before submitting
- Include comments explaining what commands do
- Provide expected output when relevant
- Use `2>/dev/null` to suppress errors in examples

#### Security Information
- Verify CVE numbers and details
- Include affected versions
- Provide working PoC when possible (ethically)
- Add references to official advisories

#### Examples
- Use realistic but anonymized examples
- Include both successful and failed scenarios
- Explain the context and expected results

### Metadata

Always include metadata at the end:
```markdown
## Metadata

- **Template version:** 1.0
- **Last updated:** December 2024
- **Contributor:** Your Name/Organization
- **Sources verified:** Yes
```

## ✅ Submission Process

### Before Submitting

- [ ] Documentation follows the template structure
- [ ] All paths and commands are verified
- [ ] Multi-OS support is included where applicable
- [ ] Navigation is updated in `mkdocs.yml`
- [ ] Local testing completed (`mkdocs serve`)
- [ ] No spelling or grammar errors
- [ ] Metadata section is complete

### Review Process

1. Maintainers will review your PR
2. They may request changes or clarifications
3. Once approved, your contribution will be merged
4. Your name will be added to the contributors list

### After Merge

- Your contribution will be live on the website
- You'll be credited in the documentation
- Thank you for making ConfigFinder better! 🎉

## 🎯 Priority Areas

We especially need contributions for:

- **Cloud Services**: AWS, Azure, GCP configurations
- **Container Tools**: Docker, Kubernetes, Podman
- **CI/CD**: Jenkins, GitLab CI, GitHub Actions
- **Monitoring**: Prometheus, Grafana, ELK Stack
- **Mail Servers**: Postfix, Sendmail, Exchange
- **Proxy/Load Balancers**: HAProxy, Traefik, Envoy

## 📞 Questions?

- Open an issue for questions
- Email: epihack.benin@gmail.com
- Check existing documentation for examples

## 🙏 Thank You!

Every contribution, no matter how small, makes ConfigFinder more valuable for the security community.

---

**Happy Contributing!** 🚀
