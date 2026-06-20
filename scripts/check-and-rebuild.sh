#!/bin/bash
# =============================================================================
# check-and-rebuild.sh
# Invoked by APT hook to check NGINX version changes and run rebuilder
# =============================================================================

if dpkg -l nginx-core 2>/dev/null | grep -q ^ii; then
    INSTALLED=$(dpkg -l nginx-core | grep ^ii | awk '{print $3}')
    PREV_VERSION=$(cat /tmp/nginx-prev-version 2>/dev/null)
    if [ "$INSTALLED" != "$PREV_VERSION" ]; then
        echo "[APT Hook] NGINX version changed from '$PREV_VERSION' to '$INSTALLED'. Rebuilding ModSecurity connector..."
        /opt/ModSecurity/WAF_GUI/scripts/rebuild-modsecurity-nginx.sh >> /var/log/nginx-modsec-rebuild.log 2>&1 && \
        echo '[APT Hook] ModSecurity connector rebuilt successfully.' || \
        echo '[APT Hook] WARNING: ModSecurity connector rebuild FAILED! Check /var/log/nginx-modsec-rebuild.log'
    fi
    echo "$INSTALLED" > /tmp/nginx-prev-version
fi
