#!/bin/bash
# High-performance kernel-level network configuration to mitigate TCP SYN floods and high connection rate DDoS.
# Must be run as root.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "Optimizing kernel settings for high connection rate and SYN flood mitigation..."

# Write configurations
SYSCTL_CONF="/etc/sysctl.d/99-waf-ddos.conf"
echo "# WAF DDoS Mitigation Kernel Settings" > "$SYSCTL_CONF"

# 1. Enable TCP SYN cookies (Mitigate SYN flood attacks)
echo "net.ipv4.tcp_syncookies = 1" >> "$SYSCTL_CONF"

# 2. Limit the number of times synacks are retransmitted (Drop dead connections faster)
echo "net.ipv4.tcp_synack_retries = 2" >> "$SYSCTL_CONF"
echo "net.ipv4.tcp_syn_retries = 3" >> "$SYSCTL_CONF"

# 3. Increase the maximum backlog of half-open TCP connections (TCP SYN backlog queue size)
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> "$SYSCTL_CONF"

# 4. Increase maximum connection queue size (sockets waiting to be accepted)
echo "net.core.somaxconn = 65535" >> "$SYSCTL_CONF"

# 5. Increase maximum network receive backlog (interface queue size)
echo "net.core.netdev_max_backlog = 65536" >> "$SYSCTL_CONF"

# 6. Decrease TCP FIN timeout to release dead sockets faster
echo "net.ipv4.tcp_fin_timeout = 15" >> "$SYSCTL_CONF"

# 7. Enable TCP Time-Wait socket reuse for keepalive connections
echo "net.ipv4.tcp_tw_reuse = 1" >> "$SYSCTL_CONF"

# 8. Increase maximum tracking limits for conntrack (to prevent table full crashes)
echo "net.netfilter.nf_conntrack_max = 262144" >> "$SYSCTL_CONF" 2>/dev/null || true

# Apply changes immediately
sysctl --system

echo "System settings applied successfully! Configurations saved to $SYSCTL_CONF"
