#!/bin/bash
# =============================================================================
# install-resty-core.sh
# Downloads and installs lua-resty-core and lua-resty-lrucache into system path
# =============================================================================

set -e

LUA_SHARE_DIR="/usr/share/lua/5.1"
TMP_DIR="/tmp/resty-core-install"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root. Try: sudo $0"
fi

log "Preparing temp directory..."
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

log "Downloading lua-resty-core v0.1.28..."
wget -q "https://github.com/openresty/lua-resty-core/archive/refs/tags/v0.1.28.tar.gz" -O core.tar.gz
tar -xzf core.tar.gz

log "Downloading lua-resty-lrucache v0.13..."
wget -q "https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v0.13.tar.gz" -O lrucache.tar.gz
tar -xzf lrucache.tar.gz

log "Installing to $LUA_SHARE_DIR/resty/..."
mkdir -p "$LUA_SHARE_DIR/resty"

# Copy core files
cp -r lua-resty-core-0.1.28/lib/resty/* "$LUA_SHARE_DIR/resty/"
# Copy lrucache files
cp -r lua-resty-lrucache-0.13/lib/resty/* "$LUA_SHARE_DIR/resty/"

# Clean up
cd /
rm -rf "$TMP_DIR"

success "Successfully installed lua-resty-core and lua-resty-lrucache libraries!"
