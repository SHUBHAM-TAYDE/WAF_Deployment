# WAF Architecture

This document outlines the architectural flow of our Enterprise WAF Deployment.

## Traffic Flow

1. **Client Request**: The client sends an HTTP/HTTPS request to the application domain (`YOUR_DOMAIN`).
2. **NGINX / ModSecurity**: The request is intercepted by the NGINX reverse proxy. ModSecurity analyzes the request against the OWASP Core Rule Set.
3. **Rule Evaluation**:
   - *Malicious Request*: If the payload matches a known threat (e.g., SQLi, XSS), ModSecurity blocks the request and logs the event. NGINX returns a `403 Forbidden` error to the client.
   - *Legitimate Request*: If the request is safe, NGINX forwards it to the upstream application servers (`backend.example.com`).
4. **Upstream Application**: The backend server processes the safe request and sends the response back through NGINX to the client.

## Technologies Used
- NGINX: Reverse proxy and web server.
- ModSecurity (libmodsecurity3): Dynamic HTTP traffic analysis and WAF engine.
- OWASP ModSecurity Core Rule Set (CRS): Pre-configured rules to protect against top web application security risks.

## Security Features
- Real-time HTTP traffic monitoring and filtering.
- Protection against the OWASP Top 10 vulnerabilities.
- Data leak prevention and strict protocol validation.
- Extensive logging of security events for analysis.
