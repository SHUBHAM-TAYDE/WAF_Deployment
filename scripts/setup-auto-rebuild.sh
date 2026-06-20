#!/bin/bash
# =============================================================================
# setup-auto-rebuild.sh
# One-time setup: installs the APT hook and removes the NGINX hold
# =============================================================================
# Run once as root:
#   sudo bash /opt/ModSecurity/WAF_GUI/scripts/setup-auto-rebuild.sh
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()     { echo -e "${BLUE}[SETUP]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash $0"
    exit 1
fi

log "Setting up CyberSentinel ModSecurity Auto-Rebuild..."

# Step 1: Make the rebuild script executable
chmod +x /opt/ModSecurity/WAF_GUI/scripts/rebuild-modsecurity-nginx.sh
success "Rebuild script made executable."

# Step 2: Install the APT hook
cp /opt/ModSecurity/WAF_GUI/scripts/99-modsecurity-rebuild.conf \
   /etc/apt/apt.conf.d/99-modsecurity-rebuild
success "APT hook installed at /etc/apt/apt.conf.d/99-modsecurity-rebuild"

# Step 3: Save current nginx version as baseline
CURRENT_VERSION=$(dpkg -l nginx-core | grep ^ii | awk '{print $3}')
echo "$CURRENT_VERSION" > /tmp/nginx-prev-version
success "Baseline NGINX version saved: $CURRENT_VERSION"

# Step 4: Remove the apt hold on nginx packages
log "Removing apt hold on NGINX packages..."
apt-mark unhold nginx nginx-core nginx-common \
    libnginx-mod-http-geoip2 \
    libnginx-mod-http-image-filter \
    libnginx-mod-http-xslt-filter \
    libnginx-mod-mail \
    libnginx-mod-stream \
    libnginx-mod-stream-geoip2 2>/dev/null || true
success "NGINX packages are now free to receive security updates."

# Step 5: Install required build tools if missing
log "Ensuring build dependencies are installed..."
apt-get install -y -q \
    build-essential \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget 2>/dev/null
success "Build dependencies OK."

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Auto-rebuild setup complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "  What happens now:"
echo "  • NGINX can receive ALL future security updates normally"
echo "  • After each NGINX upgrade, APT will automatically trigger"
echo "    rebuild-modsecurity-nginx.sh to recompile the module"
echo "  • ModSecurity will always stay compatible with NGINX"
echo ""
echo "  To manually trigger a rebuild anytime:"
echo "  sudo /opt/ModSecurity/WAF_GUI/scripts/rebuild-modsecurity-nginx.sh"
echo ""
echo "  Rebuild log file:"
echo "  /var/log/nginx-modsec-rebuild.log"
