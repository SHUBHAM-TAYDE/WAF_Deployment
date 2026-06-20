#!/bin/bash
# =============================================================================
# update-crs.sh — CyberSentinel OWASP CRS Auto-Updater
# =============================================================================
# Pulls the latest OWASP Core Rule Set from the upstream git repository,
# verifies the update, and reloads OpenResty/Nginx to apply the new rules.
#
# Schedule: Run weekly via cron (see /etc/cron.weekly/update-owasp-crs)
# Log file: /var/log/crs-update.log
#
# Usage: sudo /opt/ModSecurity/WAF_GUI/scripts/update-crs.sh
# =============================================================================

set -euo pipefail

# --- Configuration ---
CRS_DIR="/etc/nginx/modsec/coreruleset"
LOG_FILE="/var/log/crs-update.log"
NGINX_BIN="openresty"          # Change to "nginx" if not using OpenResty
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

# --- Colors (only when running interactively) ---
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

log()     { echo -e "${BLUE}[${TIMESTAMP}]${NC} $*" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[OK]${NC} $*"          | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"       | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"         | tee -a "$LOG_FILE"; exit 1; }

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root. Try: sudo $0"
fi

log "============================================================"
log "  CyberSentinel OWASP CRS Update — ${TIMESTAMP}"
log "============================================================"

# --- Step 1: Verify CRS directory exists and is a git repo ---
if [ ! -d "${CRS_DIR}/.git" ]; then
    error "CRS directory '${CRS_DIR}' is not a git repository. Cannot auto-update."
fi

log "CRS git repository found at: ${CRS_DIR}"

# --- Step 2: Capture the current version before update ---
BEFORE_COMMIT=$(git -C "$CRS_DIR" rev-parse --short HEAD)
BEFORE_DATE=$(git   -C "$CRS_DIR" log -1 --format="%cd" --date=short)
log "Current CRS version: commit=${BEFORE_COMMIT} (date=${BEFORE_DATE})"

# --- Step 3: Fetch and pull latest rules ---
log "Pulling latest OWASP CRS from upstream..."
GIT_OUTPUT=$(git -C "$CRS_DIR" pull --ff-only 2>&1) || {
    warn "git pull failed. CRS was NOT updated. Aborting reload."
    echo "$GIT_OUTPUT" | tee -a "$LOG_FILE"
    exit 1
}
echo "$GIT_OUTPUT" | tee -a "$LOG_FILE"

# --- Step 4: Capture the new version after update ---
AFTER_COMMIT=$(git -C "$CRS_DIR" rev-parse --short HEAD)
AFTER_DATE=$(git   -C "$CRS_DIR" log -1 --format="%cd" --date=short)

if [ "$BEFORE_COMMIT" = "$AFTER_COMMIT" ]; then
    success "CRS is already up-to-date (commit=${AFTER_COMMIT}). No reload needed."
    log "============================================================"
    exit 0
fi

log "CRS updated: ${BEFORE_COMMIT} → ${AFTER_COMMIT} (${AFTER_DATE})"

# --- Step 5: Count rule files for verification ---
RULE_COUNT=$(find "${CRS_DIR}/rules" -name "*.conf" | wc -l)
log "Verified ${RULE_COUNT} rule files present in ${CRS_DIR}/rules/"

# --- Step 6: Test Nginx/OpenResty configuration syntax ---
log "Testing ${NGINX_BIN} configuration syntax..."
if ! ${NGINX_BIN} -t 2>&1 | tee -a "$LOG_FILE"; then
    error "Nginx config test FAILED after CRS update! Investigate before reloading."
fi
success "Nginx config syntax OK."

# --- Step 7: Reload Nginx/OpenResty to apply new rules ---
log "Reloading ${NGINX_BIN} to apply updated rules..."
systemctl reload openresty 2>/dev/null || systemctl reload nginx 2>/dev/null || {
    error "Failed to reload web server. Please reload manually: sudo systemctl reload openresty"
}
success "Web server reloaded successfully."

# --- Step 8: Final status summary ---
log ""
success "============================================================"
success "  OWASP CRS Update Complete!"
success "  Before : ${BEFORE_COMMIT} (${BEFORE_DATE})"
success "  After  : ${AFTER_COMMIT}  (${AFTER_DATE})"
success "  Rules  : ${RULE_COUNT} .conf files active"
success "============================================================"
log "Full log saved to: ${LOG_FILE}"
