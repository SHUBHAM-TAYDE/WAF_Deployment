# WAF Dashboard Backend API

This is a production-style backend API built with FastAPI to serve a modern enterprise WAF dashboard GUI. It processes local ModSecurity audit logs directly.

## Setup Instructions

1. Ensure Python 3.9+ is installed.
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure settings:
   By default, the backend looks for logs in `/var/log/modsecurity/audit/`.
   You can override configurations using environment variables or a `.env` file.

## Running the Server

Run the development server using uvicorn:
```bash
uvicorn app.main:app --reload
```

## Features

- **Log Parsing**: Parses ModSecurity concurrent JSON logs safely.
- **REST API**: Provides paginated endpoints for logs, stats, top IPs, timeline, etc.
- **WebSockets**: Streams new logs to connected clients in real-time.
- **Security**: Basic JWT authentication placeholders, secure path sanitization, and CORS support.
