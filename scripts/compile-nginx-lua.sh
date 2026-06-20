#!/bin/bash
# =============================================================================
# compile-nginx-lua.sh
# Compiles ngx_devel_kit and lua-nginx-module dynamically against NGINX 1.18.0
# Installs lua-resty-http directly into the system search path
# =============================================================================

set -e

# --- Configuration ---
BUILD_DIR="/tmp/nginx-lua-build"
NGINX_MODULES_DIR="/usr/lib/nginx/modules"
LUA_SHARE_DIR="/usr/share/lua/5.1/resty"
LOG_FILE="/var/log/nginx-lua-compile.log"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }

if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root. Try: sudo $0"
fi

log "======================================================"
log "  CyberSentinel NGINX Lua Dynamic Module Compiler"
log "======================================================"

# 1. Install prerequisites
log "Installing dependencies (developer libraries)..."
apt-get update -q
apt-get install -y -q \
    libpcre3-dev build-essential wget git 2>&1 | tee -a "$LOG_FILE"


# 2. Detect NGINX Version
NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
log "Detected running NGINX version: $NGINX_VERSION"

# 3. Prepare Build Directory
log "Preparing build directory at $BUILD_DIR..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# 4. Clone ngx_devel_kit & lua-nginx-module & luajit2
log "Cloning ngx_devel_kit..."
git clone --depth 1 -b v0.3.3 https://github.com/vision5/ngx_devel_kit.git 2>&1 | tee -a "$LOG_FILE"

log "Cloning lua-nginx-module (v0.10.26 for OpenSSL 3.0 compatibility)..."
git clone --depth 1 -b v0.10.26 https://github.com/openresty/lua-nginx-module.git 2>&1 | tee -a "$LOG_FILE"

log "Cloning OpenResty's luajit2..."
git clone --depth 1 https://github.com/openresty/luajit2.git "$BUILD_DIR/luajit2" 2>&1 | tee -a "$LOG_FILE"
cd "$BUILD_DIR/luajit2"
log "Compiling OpenResty's luajit2..."
make -j$(nproc) PREFIX=/usr/local 2>&1 | tee -a "$LOG_FILE"
make install PREFIX=/usr/local 2>&1 | tee -a "$LOG_FILE"
ldconfig
cd "$BUILD_DIR"

# 5. Get NGINX Source
NGINX_TARBALL="$BUILD_DIR/nginx-${NGINX_VERSION}.tar.gz"
NGINX_SRC_DIR="$BUILD_DIR/nginx-${NGINX_VERSION}"

# Check if cached source exists
CACHED_TARBALL="/opt/ModSecurity/nginx-${NGINX_VERSION}.tar.gz"
if [ -f "$CACHED_TARBALL" ]; then
    log "Using cached NGINX source tarball..."
    cp "$CACHED_TARBALL" "$NGINX_TARBALL"
else
    log "Downloading NGINX source..."
    wget -q "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -O "$NGINX_TARBALL"
fi
tar -xzf "$NGINX_TARBALL"

# 6. Extract configure arguments
NGINX_CONFIGURE_ARGS=$(nginx -V 2>&1 | grep "configure arguments:" | sed 's/configure arguments: //')

# Strip any original --add-dynamic-module or --add-module parameters referring to /build/ directory
# since those packaging source directories do not exist on this machine.
log "Cleaning original configure arguments..."
NGINX_CONFIGURE_ARGS=$(echo "$NGINX_CONFIGURE_ARGS" | sed -E 's/--add-dynamic-module=[^ ]*//g')
# Inject rpath to ensure loader uses /usr/local/lib for LuaJIT at runtime
NGINX_CONFIGURE_ARGS=$(echo "$NGINX_CONFIGURE_ARGS" | sed "s/--with-ld-opt='/--with-ld-opt='-Wl,-rpath,\/usr\/local\/lib /")

# 7. Compile Dynamic Modules
cd "$NGINX_SRC_DIR"
log "Configuring build flags with OpenResty LuaJIT environment..."
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# We use eval here to correctly preserve and parse single-quoted configure arguments (e.g. --with-cc-opt)
eval "./configure \
    ${NGINX_CONFIGURE_ARGS} \
    --add-dynamic-module=\"$BUILD_DIR/ngx_devel_kit\" \
    --add-dynamic-module=\"$BUILD_DIR/lua-nginx-module\" \
    2>&1 | tee -a \"$LOG_FILE\""

log "Compiling dynamic modules..."
make -j$(nproc) modules 2>&1 | tee -a "$LOG_FILE"

# 8. Verify compiled binaries
NDK_SO="$NGINX_SRC_DIR/objs/ndk_http_module.so"
LUA_SO="$NGINX_SRC_DIR/objs/ngx_http_lua_module.so"

if [ ! -f "$NDK_SO" ] || [ ! -f "$LUA_SO" ]; then
    error "Compilation failed. Dynamic module binaries not found."
fi

# 9. Copy modules to NGINX directory
log "Copying modules to $NGINX_MODULES_DIR..."
cp "$NDK_SO" "$NGINX_MODULES_DIR/ndk_http_module.so"
cp "$LUA_SO" "$NGINX_MODULES_DIR/ngx_http_lua_module.so"
chmod 644 "$NGINX_MODULES_DIR/ndk_http_module.so"
chmod 644 "$NGINX_MODULES_DIR/ngx_http_lua_module.so"

# 10. Enable modules in NGINX configuration loading path
log "Creating module enablement files..."
echo "load_module modules/ndk_http_module.so;" > /etc/nginx/modules-enabled/10-mod-ndk.conf
echo "load_module modules/ngx_http_lua_module.so;" > /etc/nginx/modules-enabled/50-mod-lua.conf

# 11. Install lua-resty-http library directly
log "Installing lua-resty-http modules to $LUA_SHARE_DIR..."
mkdir -p "$LUA_SHARE_DIR"
wget -q "https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http.lua" -O "$LUA_SHARE_DIR/http.lua"
wget -q "https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_headers.lua" -O "$LUA_SHARE_DIR/http_headers.lua"
chmod 644 "$LUA_SHARE_DIR/http.lua" "$LUA_SHARE_DIR/http_headers.lua"
success "Installed lua-resty-http libraries."

# 12. Test NGINX Configuration
log "Testing NGINX configuration..."
if nginx -t 2>&1 | tee -a "$LOG_FILE"; then
    success "======================================================"
    success "  Nginx Lua Modules compiled and loaded successfully!"
    success "======================================================"
else
    error "NGINX config test failed after module enablement. Check logs."
fi

# 13. Clean up
rm -rf "$BUILD_DIR"
