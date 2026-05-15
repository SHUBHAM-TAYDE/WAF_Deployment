# Testing Guide

After successfully deploying the WAF, you should validate its effectiveness using the test payloads provided in the `test-payloads/` directory.

## How to Test

You can use tools like `curl` to send malicious payloads to your WAF and ensure they are blocked. Replace `YOUR_DOMAIN` with your actual domain or IP address.

### 1. SQL Injection (SQLi)
Attempt to send a malicious SQL query parameter:
```bash
curl -i "http://YOUR_DOMAIN/?id=1' OR '1'='1"
```
*Expected Result*: HTTP 403 Forbidden. The WAF logs will show a CRS rule match for SQL injection.

### 2. Cross-Site Scripting (XSS)
Attempt to inject a script tag:
```bash
curl -i "http://YOUR_DOMAIN/?search=<script>alert('xss')</script>"
```
*Expected Result*: HTTP 403 Forbidden. The WAF logs will show a CRS rule match for XSS.

### 3. Local File Inclusion (LFI)
Attempt to access a sensitive system file:
```bash
curl -i "http://YOUR_DOMAIN/?file=../../../../etc/passwd"
```
*Expected Result*: HTTP 403 Forbidden. The WAF logs will show a CRS rule match for path traversal/LFI.

## Reviewing Logs
To confirm that ModSecurity is blocking the requests, monitor the ModSecurity audit logs:
```bash
sudo tail -f /var/log/modsec_audit.log
```
You should see entries detailing the exact rule triggered by the test payload.
