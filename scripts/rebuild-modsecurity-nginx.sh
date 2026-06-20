#!/bin/bash
# =============================================================================
# rebuild-modsecurity-nginx.sh
# =============================================================================
# Automatically recompiles the ModSecurity-NGINX connector module against
# the currently installed version of NGINX.
#
# Run this script whenever NGINX is upgraded, or let the APT hook run it
# automatically. Requires root privileges.
#
# Usage:
#   sudo /opt/ModSecurity/WAF_GUI/scripts/rebuild-modsecurity-nginx.sh
# =============================================================================

set -e

# --- Configuration ---
MODSEC_CONNECTOR_SRC="/opt/ModSecurity/ModSecurity-nginx"
MODSEC_LIB_DIR="/usr/local/modsecurity"
NGINX_MODULE_DEST="/etc/nginx/modules/ngx_http_modsecurity_module.so"
BUILD_DIR="/tmp/nginx-modsec-rebuild"
LOG_FILE="/var/log/nginx-modsec-rebuild.log"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root. Try: sudo $0"
fi

log "======================================================"
log "  CyberSentinel ModSecurity-NGINX Rebuild Script"
log "======================================================"

# --- Step 1: Detect installed NGINX version ---
NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
if [ -z "$NGINX_VERSION" ]; then
    error "Could not detect NGINX version. Is NGINX installed?"
fi
log "Detected NGINX version: $NGINX_VERSION"

# --- Step 2: Check if the connector source exists ---
if [ ! -d "$MODSEC_CONNECTOR_SRC" ]; then
    error "ModSecurity-NGINX connector source not found at $MODSEC_CONNECTOR_SRC"
fi
log "Connector source found at: $MODSEC_CONNECTOR_SRC"

# --- Step 3: Prepare build directory ---
log "Preparing build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# --- Step 4: Get NGINX source matching installed version ---
NGINX_TARBALL="$BUILD_DIR/nginx-${NGINX_VERSION}.tar.gz"
NGINX_SRC_DIR="$BUILD_DIR/nginx-${NGINX_VERSION}"

# Check if source tarball already exists in /opt/ModSecurity
EXISTING_TARBALL="/opt/ModSecurity/nginx-${NGINX_VERSION}.tar.gz"
if [ -f "$EXISTING_TARBALL" ]; then
    log "Found existing NGINX source tarball at $EXISTING_TARBALL"
    cp "$EXISTING_TARBALL" "$NGINX_TARBALL"
else
    log "Downloading NGINX $NGINX_VERSION source..."
    if ! wget -q --timeout=60 "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -O "$NGINX_TARBALL"; then
        error "Failed to download NGINX $NGINX_VERSION source. Check internet connection."
    fi
    # Cache it for future use
    cp "$NGINX_TARBALL" "$EXISTING_TARBALL"
    log "Cached source tarball at $EXISTING_TARBALL"
fi

# --- Step 5: Extract NGINX source ---
log "Extracting NGINX source..."
tar -xzf "$NGINX_TARBALL" -C "$BUILD_DIR"

# --- Step 6: Get NGINX configure arguments from running binary ---
log "Extracting NGINX build configuration..."
NGINX_CONFIGURE_ARGS=$(nginx -V 2>&1 | grep "configure arguments:" | sed 's/configure arguments: //')
log "Original configure args: $NGINX_CONFIGURE_ARGS"

# --- Step 7: Compile the dynamic module only ---
log "Compiling ModSecurity-NGINX dynamic module..."
cd "$NGINX_SRC_DIR"

# Run configure with the original args + add-dynamic-module pointing to connector
./configure \
    ${NGINX_CONFIGURE_ARGS} \
    --add-dynamic-module="$MODSEC_CONNECTOR_SRC" \
    2>&1 | tee -a "$LOG_FILE"

# Build only the modules (not the full NGINX binary)
make -j$(nproc) modules 2>&1 | tee -a "$LOG_FILE"

# --- Step 8: Verify the compiled module ---
COMPILED_MODULE="$NGINX_SRC_DIR/objs/ngx_http_modsecurity_module.so"
if [ ! -f "$COMPILED_MODULE" ]; then
    error "Compiled module not found at $COMPILED_MODULE. Build may have failed."
fi

COMPILED_SIZE=$(du -sh "$COMPILED_MODULE" | cut -f1)
log "Compiled module: $COMPILED_MODULE ($COMPILED_SIZE)"

# --- Step 9: Backup the old module ---
if [ -f "$NGINX_MODULE_DEST" ]; then
    BACKUP_PATH="${NGINX_MODULE_DEST}.backup-$(date '+%Y%m%d-%H%M%S')"
    log "Backing up existing module to $BACKUP_PATH"
    cp "$NGINX_MODULE_DEST" "$BACKUP_PATH"
fi

# --- Step 10: Install the new module ---
log "Installing new module to $NGINX_MODULE_DEST"
cp "$COMPILED_MODULE" "$NGINX_MODULE_DEST"
chmod 644 "$NGINX_MODULE_DEST"

# --- Step 11: Test NGINX configuration ---
log "Testing NGINX configuration..."
if ! nginx -t 2>&1 | tee -a "$LOG_FILE"; then
    warn "NGINX config test failed! Restoring backup module..."
    if [ -f "$BACKUP_PATH" ]; then
        cp "$BACKUP_PATH" "$NGINX_MODULE_DEST"
    fi
    error "Restored backup. Please check NGINX configuration manually."
fi

# --- Step 12: Reload NGINX ---
log "Reloading NGINX..."
systemctl reload nginx

# --- Step 13: Verify NGINX is running ---
sleep 1
if systemctl is-active --quiet nginx; then
    success "NGINX is running successfully with the new ModSecurity module!"
else
    error "NGINX failed to start after module replacement. Check logs."
fi

# --- Step 14: Cleanup build directory ---
log "Cleaning up build directory..."
rm -rf "$BUILD_DIR"

# --- Done ---
log ""
success "======================================================"
success "  ModSecurity-NGINX rebuild complete!"
success "  NGINX $NGINX_VERSION + ModSecurity v3 active."
success "======================================================"
log "Full log saved to: $LOG_FILE"
