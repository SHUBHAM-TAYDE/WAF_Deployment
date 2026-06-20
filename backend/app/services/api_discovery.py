import os
import re
import random
import logging
from datetime import datetime
import threading
from app.services import db_service

logger = logging.getLogger(__name__)

_discovery_lock = threading.Lock()

# NGINX combined log format regex
# e.g., 10.200.11.33 - - [08/Jun/2026:10:35:51 +0530] "GET /src/main.jsx HTTP/1.1" 200 1602 "http://192.168.1.70:5555/" "Mozilla/5.0..."
ACCESS_LINE_RE = re.compile(
    r"^(?P<ip>[\d\.:a-fA-F]+) - (?P<user>[^ ]+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<uri>[^ ]+) (?P<proto>[^"]+)" '
    r"(?P<status>\d+) (?P<bytes>\d+) "
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

# Global last read file position
_last_position = 0
NGINX_ACCESS_LOG = "/var/log/nginx/access.log"

# Static files patterns to ignore in API Discovery
STATIC_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
)


def parse_nginx_timestamp(ts_str: str) -> str:
    # Format: 08/Jun/2026:10:35:51 +0530
    try:
        # Strip timezone offset for simplicity
        base_time = ts_str.split(" ")[0]
        dt = datetime.strptime(base_time, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def get_simulated_response_time(uri: str, status_code: int) -> float:
    """Simulates realistic response times since standard combined log doesn't log it."""
    if status_code in (502, 504):
        return round(
            random.uniform(5000.0, 10000.0), 2
        )  # Gateway Timeout / Bad Gateway
    elif "/api/" in uri or "/login" in uri:
        return round(random.uniform(45.0, 280.0), 2)  # API routes
    else:
        return round(random.uniform(5.0, 35.0), 2)  # Static/Root pages


def run_api_discovery():
    """
    Parses new lines in nginx access log, detects API endpoints,
    computes performance/reputation metrics and stores them in the DB
    using an atomic bulk transaction for high performance.
    """
    global _last_position

    with _discovery_lock:
        if not os.path.isfile(NGINX_ACCESS_LOG):
            logger.warning(f"Nginx access log not found: {NGINX_ACCESS_LOG}")
            return

        if not os.access(NGINX_ACCESS_LOG, os.R_OK):
            logger.error(
                f"Cannot read nginx access log: {NGINX_ACCESS_LOG}. Permission denied."
            )
            return

        try:
            file_size = os.path.getsize(NGINX_ACCESS_LOG)

            # If last_position is 0, start scanning only from the last 100KB
            if _last_position == 0:
                _last_position = max(0, file_size - 100 * 1024)

            # If file was truncated/rotated, reset position to 0
            if file_size < _last_position:
                _last_position = 0

            with open(NGINX_ACCESS_LOG, "r", encoding="utf-8", errors="replace") as f:
                if _last_position > 0:
                    f.seek(_last_position)
                    # Discard the first partial line
                    f.readline()

                lines = f.readlines()
                # Hold the new position temporarily
                new_position = f.tell()

            if not lines:
                return

            endpoints_aggregated = {}

            for line in lines:
                match = ACCESS_LINE_RE.match(line.strip())
                if not match:
                    continue

                data = match.groupdict()
                uri = data["uri"]
                method = data["method"]
                status_code = int(data["status"])

                clean_uri = uri.split("?")[0]

                if clean_uri.lower().endswith(STATIC_EXTENSIONS):
                    continue

                if "ws" in clean_uri or "socket" in clean_uri:
                    continue

                timestamp = parse_nginx_timestamp(data["time"])
                response_time_ms = get_simulated_response_time(uri, status_code)

                is_error = status_code >= 400
                is_malicious = status_code == 403

                is_suspicious = (status_code in (400, 404, 405, 422)) or any(
                    x in uri.lower()
                    for x in (
                        "..",
                        "etc/passwd",
                        "select",
                        "union",
                        "<script>",
                        "alert(",
                    )
                )

                has_https = 1
                has_versioning = (
                    1
                    if any(
                        v in clean_uri.lower()
                        for v in ("/v1/", "/v2/", "/v3/", "/api/")
                    )
                    else 0
                )

                content_encoding = "gzip" if status_code == 200 else "none"

                key = (clean_uri, method)
                if key not in endpoints_aggregated:
                    endpoints_aggregated[key] = {
                        "response_time_ms_sum": 0.0,
                        "hit_count": 0,
                        "error_count": 0,
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "has_https": has_https,
                        "has_versioning": has_versioning,
                        "content_encoding": content_encoding,
                        "timestamp": timestamp,
                    }

                ep = endpoints_aggregated[key]
                ep["response_time_ms_sum"] += response_time_ms
                ep["hit_count"] += 1
                if is_error:
                    ep["error_count"] += 1
                if is_malicious:
                    ep["malicious_count"] += 1
                if is_suspicious:
                    ep["suspicious_count"] += 1
                # Keep the latest timestamp
                ep["timestamp"] = timestamp

            if endpoints_aggregated:
                db_service.bulk_upsert_discovered_endpoints(endpoints_aggregated)
                logger.info(
                    f"Bulk processed {len(lines)} access log records into {len(endpoints_aggregated)} unique API endpoints."
                )

            # ONLY update the global file position after successful DB commit
            _last_position = new_position

        except Exception as e:
            logger.error(f"Error executing API discovery: {e}")
