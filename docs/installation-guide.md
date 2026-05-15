# Installation Guide

Follow these steps to deploy the Enterprise WAF on your Linux-based environment.

## Prerequisites
- A Linux-based server (e.g., Ubuntu/Debian or RHEL/CentOS).
- `root` or `sudo` privileges.
- Network access to update packages and download NGINX/ModSecurity source codes.

## Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-org/waf-deployment.git
   cd waf-deployment
   ```

2. **Run the Installation Script**
   Execute the automated installation script. This script will install dependencies, compile ModSecurity, configure NGINX, and download the OWASP CRS.
   ```bash
   chmod +x scripts/install.sh
   sudo ./scripts/install.sh
   ```

3. **Verify the Installation**
   Check that NGINX is running and successfully loaded the ModSecurity module:
   ```bash
   sudo systemctl status nginx
   nginx -V 2>&1 | grep modsecurity
   ```

4. **Update Configuration (Optional)**
   You can adjust the WAF rules and settings in the NGINX configuration files (typically `/etc/nginx/nginx.conf` and `/etc/nginx/modsec/main.conf`). Ensure your upstream block points to `backend.example.com` or your internal application IP (`YOUR_IP`).

## Troubleshooting
If the service fails to start, check the NGINX error logs:
```bash
sudo tail -f /var/log/nginx/error.log
```
