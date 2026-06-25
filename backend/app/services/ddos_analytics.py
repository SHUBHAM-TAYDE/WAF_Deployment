import os
import re
import logging
from typing import Dict, Any
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

ERROR_LOG_PATH = "/var/log/nginx/error.log"

# Regex for NGINX rate limiting error/warn log
# Example: 2023/10/25 10:15:30 [error] 1234#0: *5 limiting requests, excess: 50.123 by zone "waf_ddos_req", client: 192.168.1.100...
# Example: 2026/06/19 10:19:07 [warn] 1801952#1801952: *50868 delaying request, excess: 0.610, by zone "api_limit", client: 10.200.11.19...
RATE_LIMIT_REGEX = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?:error|warn)\] .*? (?:limiting|delaying) (?:requests|connections|request).*? client: (?P<client>[^,]+),"
)

# Keywords that must appear in log line to match rate limit events
RATE_LIMIT_KEYWORDS = {"limiting requests", "limiting connections", "delaying request", "delaying connections"}


def _tail_file(filepath: str, n: int) -> list:
    """
    Memory-efficient tail: reads only the last n lines of a file
    without loading the entire file into RAM. Uses binary reverse scan.
    """
    try:
        with open(filepath, "rb") as f:
            # Seek to end
            f.seek(0, 2)
            file_size = f.tell()
            if file_size == 0:
                return []

            # Walk backwards collecting newlines
            lines_found = []
            block_size = 8192
            position = file_size

            while position > 0 and len(lines_found) <= n:
                read_size = min(block_size, position)
                position -= read_size
                f.seek(position)
                block = f.read(read_size)
                lines_found = block.split(b"\n") + lines_found

            # Decode and return last n lines
            decoded = []
            for line in lines_found[-n:]:
                try:
                    decoded.append(line.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            return decoded
    except Exception as e:
        logger.error(f"Error tailing file {filepath}: {e}")
        return []


def get_ddos_analytics(limit_lines: int = 2000) -> Dict[str, Any]:
    """
    Parses the NGINX error log for rate-limiting events and aggregates them.
    Uses memory-efficient tail reading instead of loading the entire file.
    Returns timeseries data, top blocked IPs, total blocks and unique IP count.
    """
    if not os.path.exists(ERROR_LOG_PATH):
        return {"timeline": [], "top_ips": [], "total_blocks": 0, "total_unique_ips": 0}

    timeline_data = defaultdict(int)
    ip_counts = defaultdict(int)
    total_blocks = 0

    try:
        # FIX 5: Use O(1)-memory tail reading instead of f.readlines()
        lines = _tail_file(ERROR_LOG_PATH, limit_lines)

        for line in lines:
            if not any(k in line for k in RATE_LIMIT_KEYWORDS):
                continue

            match = RATE_LIMIT_REGEX.search(line)
            if match:
                total_blocks += 1
                date_str = match.group("date")
                client_ip = match.group("client").strip()

                try:
                    # Format: YYYY/MM/DD HH:MM:SS
                    dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
                    rounded_minute = (dt.minute // 15) * 15
                    # FIX 6: Include date so chart is unambiguous across day boundaries
                    time_bucket = f"{dt.strftime('%m/%d')} {dt.hour:02d}:{rounded_minute:02d}"
                    timeline_data[time_bucket] += 1
                except ValueError:
                    pass

                ip_counts[client_ip] += 1

    except Exception as e:
        logger.error(f"Error parsing NGINX error log for DDoS analytics: {e}")

    # Sort timeline by (date, time) and take last 60 data points for chart
    sorted_times = sorted(timeline_data.keys())
    sorted_times = sorted_times[-60:]

    formatted_timeline = [
        {"time": t, "blocked": timeline_data[t]} for t in sorted_times
    ]

    # Total unique IPs across all log entries (not just top 10)
    total_unique_ips = len(ip_counts)

    # Format top 10 IPs
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    formatted_ips = [{"ip": ip, "count": count} for ip, count in sorted_ips]

    return {
        "timeline": formatted_timeline,
        "top_ips": formatted_ips,
        "total_blocks": total_blocks,
        "total_unique_ips": total_unique_ips,  # FIX 11: true count, not capped at 10
    }
