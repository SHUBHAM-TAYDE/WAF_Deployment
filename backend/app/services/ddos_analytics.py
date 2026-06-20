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


def get_ddos_analytics(limit_lines: int = 2000) -> Dict[str, Any]:
    """
    Parses the NGINX error log for rate-limiting events and aggregates them.
    Returns timeseries data and top blocked IPs.
    """
    if not os.path.exists(ERROR_LOG_PATH):
        return {"timeline": [], "top_ips": [], "total_blocks": 0}

    timeline_data = defaultdict(int)
    ip_counts = defaultdict(int)
    total_blocks = 0

    try:
        # Read the last N lines of the error log efficiently
        with open(ERROR_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            # We will read everything if the file is small, or just scan it
            lines = f.readlines()
            # Just take the last limit_lines
            if len(lines) > limit_lines:
                lines = lines[-limit_lines:]

            for line in lines:
                if any(k in line for k in ["limiting requests", "limiting connections", "delaying request", "delaying connections"]):
                    match = RATE_LIMIT_REGEX.search(line)
                    if match:
                        total_blocks += 1
                        date_str = match.group("date")
                        client_ip = match.group("client")

                        # Parse date to round down to the nearest 15-minute interval
                        try:
                            # Format: YYYY/MM/DD HH:MM:SS
                            dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
                            rounded_minute = (dt.minute // 15) * 15
                            time_bucket = f"{dt.hour:02d}:{rounded_minute:02d}"
                            timeline_data[time_bucket] += 1
                        except ValueError:
                            pass

                        ip_counts[client_ip] += 1

    except Exception as e:
        logger.error(f"Error parsing NGINX error log for DDoS analytics: {e}")

    # Format timeline for Recharts (AreaChart)
    # We will sort by time and maybe fill in gaps if necessary
    sorted_times = sorted(timeline_data.keys())
    # Keep last 60 points for the chart
    sorted_times = sorted_times[-60:]

    formatted_timeline = [
        {"time": t, "blocked": timeline_data[t]} for t in sorted_times
    ]

    # Format top IPs
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    formatted_ips = [{"ip": ip, "count": count} for ip, count in sorted_ips]

    return {
        "timeline": formatted_timeline,
        "top_ips": formatted_ips,
        "total_blocks": total_blocks,
    }
