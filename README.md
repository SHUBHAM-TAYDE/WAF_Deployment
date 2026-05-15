# Enterprise WAF Framework

## NGINX + ModSecurity + OWASP CRS

Production-ready automated Web Application Firewall deployment framework based on:

* NGINX
* ModSecurity v3
* OWASP Core Rule Set (CRS)

This project provides an enterprise-grade automated WAF deployment framework with:

* Automated installation
* Interactive deployment flow
* ModSecurity integration
* OWASP CRS deployment
* Security hardening
* Automated testing
* Audit log validation
* Rollback support
* Backup support
* Enterprise logging

---

# Architecture Overview

```text
                ┌─────────────────────┐
                │     Client/User     │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │        NGINX        │
                │   Reverse Proxy     │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    ModSecurity      │
                │   WAF Inspection    │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │     OWASP CRS       │
                │ Security Rule Engine│
                └──────────┬──────────┘
                           │
            ┌──────────────┴──────────────┐
            │                             │
            ▼                             ▼
    Block Malicious              Forward Legitimate
        Requests                        Traffic
```

---

# Features

* Enterprise-grade WAF deployment
* Interactive step-by-step installation
* Automatic NGINX installation
* ModSecurity v3 compilation and deployment
* OWASP CRS integration
* Automated CRS tuning
* Security headers hardening
* Audit logging
* Attack simulation testing
* Rollback support
* Backup support
* Production-safe validation
* Modular Bash scripting

---

# Technologies Used

## NGINX

Used as:

* Reverse Proxy
* Load Balancer
* HTTP/HTTPS Server
* Traffic handler

Why used:

* High performance
* Lightweight
* Enterprise stable
* Supports dynamic modules
* Excellent reverse proxy capabilities

---

## ModSecurity

Used as:

* Web Application Firewall Engine
* HTTP request inspection engine

Why used:

* Detects malicious requests
* Supports custom security rules
* Enterprise-grade inspection engine
* Integrates with NGINX

---

## OWASP CRS

Used as:

* Prebuilt security ruleset

Provides protection against:

* SQL Injection
* XSS
* LFI/RFI
* Path Traversal
* Protocol attacks
* Malicious payloads

---

# Project Structure

```text
enterprise-waf-framework/
│
├── waf_install.sh
├── README.md
│
├── logs/
├── backups/
├── configs/
├── temp/
├── rollback/
│
└── test-payloads/
```

---

# Requirements

## Supported OS

* Ubuntu
* Debian

## Recommended Server

* 2 CPU
* 4 GB RAM
* 20 GB Storage

## Required Privileges

Run as:

```bash
sudo
```

---

# Installation Guide

## 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/enterprise-waf-framework.git
```

## 2. Move Into Project

```bash
cd enterprise-waf-framework
```

## 3. Make Script Executable

```bash
chmod +x waf_install.sh
```

## 4. Run Installer

```bash
sudo ./waf_install.sh
```

---

# Installation Flow

The script performs:

1. Dependency installation
2. NGINX installation
3. ModSecurity compilation
4. NGINX connector compilation
5. OWASP CRS deployment
6. WAF configuration
7. Security hardening
8. Attack simulation testing
9. Log validation
10. Health checks

---

# Important Configuration Paths

## NGINX

```text
/etc/nginx/nginx.conf
/etc/nginx/conf.d/
/etc/nginx/sites-enabled/
/etc/nginx/sites-available/
```

---

## ModSecurity

```text
/etc/nginx/modsec/
/etc/nginx/modsec/modsecurity.conf
/etc/nginx/modsec/main.conf
```

---

## OWASP CRS

```text
/etc/nginx/modsec/coreruleset/
```

---

## Custom CRS Rules

```text
/etc/nginx/modsec/custom-rules/
```

---

## Logs

```text
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/modsec_audit.log
```

---

# How the WAF Works

1. Client sends request
2. NGINX receives request
3. ModSecurity intercepts request
4. OWASP CRS inspects payload
5. Malicious requests are blocked
6. Legitimate traffic is forwarded
7. Audit logs are generated

---

# Security Features

* SQL Injection Protection
* XSS Protection
* LFI Protection
* Path Traversal Protection
* Request Inspection
* Audit Logging
* Security Headers
* CRS Anomaly Scoring

---

# Automated Testing

The installer automatically tests:

* SQL Injection blocking
* XSS blocking
* LFI blocking
* Audit log generation
* NGINX validation
* ModSecurity validation

---

# Example Attack Tests

## SQL Injection Test

```bash
curl "http://localhost/?id=' OR 1=1--"
```

---

## XSS Test

```bash
curl "http://localhost/?q=<script>alert(1)</script>"
```

---

## LFI Test

```bash
curl "http://localhost/?file=../../etc/passwd"
```

---

# Service Management

## Check NGINX Status

```bash
sudo systemctl status nginx
```

## Restart NGINX

```bash
sudo systemctl restart nginx
```

## Validate NGINX Config

```bash
sudo nginx -t
```

---

# Log Monitoring

## Monitor Access Logs

```bash
sudo tail -f /var/log/nginx/access.log
```

## Monitor Error Logs

```bash
sudo tail -f /var/log/nginx/error.log
```

## Monitor ModSecurity Audit Logs

```bash
sudo tail -f /var/log/modsec_audit.log
```

---

# Rollback & Backups

The framework automatically:

* Creates backups before modification
* Validates NGINX configuration
* Rolls back on syntax failure
* Preserves previous working state

Backups stored in:

```text
./backups/
```

---

# GitHub Push Guide

## Initialize Git

```bash
git init
```

## Add Files

```bash
git add .
```

## Commit Files

```bash
git commit -m "Initial Enterprise WAF Framework"
```

## Add GitHub Remote

```bash
git remote add origin https://github.com/YOUR_USERNAME/enterprise-waf-framework.git
```

## Push Repository

```bash
git push -u origin main
```

---

# Recommended GitHub Files

Create these files:

```text
README.md
LICENSE
.gitignore
CHANGELOG.md
```

---

# Recommended .gitignore

```text
logs/
backups/
temp/
*.log
*.tar.gz
```

---

# Future Improvements

* HAProxy integration
* Coraza support
* SIEM integration
* Docker deployment
* Kubernetes support
* Grafana dashboards
* Fail2Ban integration
* Centralized logging
* CI/CD automation

---

# Disclaimer

This project is intended for:

* Security testing
* Defensive security
* Enterprise infrastructure protection
* Educational and research purposes

Always test configurations in a lab environment before production deployment.

---

# Author

Enterprise WAF Deployment Framework
Built using:

* NGINX
* ModSecurity
* OWASP CRS
