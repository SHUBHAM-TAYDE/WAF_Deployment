#!/bin/bash

################################################################################
# Enterprise WAF Installation Framework (NGINX + ModSecurity + OWASP CRS)
# Version: 1.2.0
# Author: Senior DevSecOps Engineer (Refined by Gemini CLI)
# Description: Automated, fault-tolerant, and interactive WAF deployment.
################################################################################

# --- 9. IMPROVE BASH SAFETY ---
set -Eeuo pipefail

# Project Directories
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${BASE_DIR}/logs"
BACKUP_DIR="${BASE_DIR}/backups"
CONFIG_DIR="${BASE_DIR}/configs"
TEMP_DIR="${BASE_DIR}/temp"
ROLLBACK_DIR="${BASE_DIR}/rollback"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INSTALL_LOG="${LOG_DIR}/install_${TIMESTAMP}.log"

# Requirements-based Paths
MODSEC_PREFIX="/usr/local/modsecurity"
CRS_PATH="/etc/nginx/modsec/coreruleset"
MODSEC_VERSION="v3.0.14"
AUDIT_LOG_PATH="/var/log/modsec_audit.log"
MODSEC_SRC_DIR="/opt/ModSecurity"
ACTIVE_MODSEC_SOURCE="" # Dynamically set during installation

# Dynamically detect NGINX module directory
for dir in "/usr/lib/nginx/modules" "/usr/share/nginx/modules" "/etc/nginx/modules"; do
    if [ -d "$dir" ]; then
        NGINX_MOD_DIR="$dir"
        break
    fi
done
NGINX_MOD_DIR=${NGINX_MOD_DIR:-/etc/nginx/modules}

# CRITICAL: Create system directories immediately before any logging
mkdir -p "${LOG_DIR}" "${BACKUP_DIR}" "${CONFIG_DIR}" "${TEMP_DIR}" "${ROLLBACK_DIR}" 2>/dev/null

# Colors for Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- LOGGING FUNCTION ---
log() {
    local level=$1
    local msg=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "${INSTALL_LOG}"
}

# --- BANNER ---
show_banner() {
    clear
    echo -e "${CYAN}############################################################${NC}"
    echo -e "${CYAN}#        WAF INSTALLATION FRAMEWORK v1.2.0                 #${NC}"
    echo -e "${CYAN}#         (NGINX + ModSecurity v3 + OWASP CRS)             #${NC}"
    echo -e "${CYAN}############################################################${NC}"
    echo -e "Starting deployment at: $(date)"
    echo -e "Logs: ${INSTALL_LOG}"
    echo -e "NGINX Module Dir: ${NGINX_MOD_DIR}"
    echo ""
}

# --- ERROR HANDLING & TRAPS ---
error_handler() {
    local line_no=$1
    local exit_code=$2
    log "ERROR" "Critical failure at line ${line_no} (Exit Code: ${exit_code}). Initiating safety sequence..."
    echo -e "${RED}!!! DEPLOYMENT FAILED AT LINE ${line_no} !!!${NC}"
    echo -e "${YELLOW}Last 10 lines of the log:${NC}"
    tail -n 10 "${INSTALL_LOG}"
    echo -e "\nCheck full logs at: ${INSTALL_LOG}"
    exit "${exit_code}"
}

trap 'error_handler $LINENO $?' ERR

# --- 11. CLEANUP FUNCTION ---
cleanup() {
    log "INFO" "Cleaning up temporary build files..."
    rm -rf "${TEMP_DIR:?}"/*
    log "SUCCESS" "Cleanup completed."
}

# --- INTERACTIVE CHECKPOINT ---
confirm_step() {
    local step_name=$1
    echo -e "\n${YELLOW}>>> [CHECKPOINT] Next Step: ${step_name}${NC}"
    read -p "Do you want to proceed? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "SKIP" "User skipped step: ${step_name}"
        return 1
    fi
    return 0
}

# --- PREREQUISITES ---
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Root Check
    if [[ $EUID -ne 0 ]]; then
       log "ERROR" "This script must be run as root."
       exit 1
    fi

    # OS Detection
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            log "WARN" "Unsupported OS detected: $NAME. This script is optimized for Ubuntu/Debian."
            read -p "Proceed anyway? (y/n): " -n 1 -r
            echo ""
            # 1. Fix incorrect OS confirmation logic
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
        fi
    fi

    log "SUCCESS" "Prerequisites validated."
}

# --- BACKUP SYSTEM ---
create_backup() {
    local target=$1
    local name=$2
    if [[ -d "$target" || -f "$target" ]]; then
        log "INFO" "Backing up ${name} to ${BACKUP_DIR}..."
        tar -czf "${BACKUP_DIR}/${name}_${TIMESTAMP}.tar.gz" "$target" 2>/dev/null
        log "SUCCESS" "Backup of ${name} completed."
    fi
}

# --- SYSTEM UPDATE & DEPENDENCIES ---
install_dependencies() {
    if confirm_step "System Update & Dependencies"; then
        log "INFO" "Updating package lists..."
        apt-get update -y >> "${INSTALL_LOG}" 2>&1
        
        log "INFO" "Installing core dependencies..."
        # 6. Add missing dependencies: libssl-dev ca-certificates doxygen dh-autoreconf
        # Added libxslt1-dev to fix XSLT module error
        # Added libgd-dev libperl-dev uuid-dev for enterprise builds
        apt-get install -y apt-utils autoconf automake build-essential git \
        libcurl4-openssl-dev libgeoip-dev libmaxminddb-dev liblmdb-dev \
        libpcre3-dev libpcre2-dev libtool libxml2-dev libyajl-dev \
        liblua5.3-dev pkgconf zlib1g-dev curl wget \
        libssl-dev ca-certificates doxygen dh-autoreconf \
        libxslt1-dev libgd-dev libperl-dev uuid-dev >> "${INSTALL_LOG}" 2>&1
        log "SUCCESS" "Dependencies installed."
    fi
}


# --- NGINX INSTALLATION ---
install_nginx() {
    if confirm_step "NGINX Installation & Verification"; then
        log "INFO" "Detecting NGINX..."
        if command -v nginx &> /dev/null; then
            log "SUCCESS" "NGINX is already installed."
            if [[ ! -f /etc/nginx/nginx.conf ]]; then
                log "ERROR" "NGINX is installed but /etc/nginx/nginx.conf is missing!"
                exit 1
            fi
        else
            log "INFO" "NGINX not found. Commencing automated installation..."
            
            log "INFO" "Updating package lists..."
            apt-get update -y >> "${INSTALL_LOG}" 2>&1
            
            log "INFO" "Installing NGINX packages (nginx, nginx-common, nginx-core)..."
            # Support Ubuntu/Debian, check for broken dependencies
            apt-get install -f -y >> "${INSTALL_LOG}" 2>&1
            apt-get install -y nginx nginx-common nginx-core >> "${INSTALL_LOG}" 2>&1
            
            if ! command -v nginx &> /dev/null; then
                log "ERROR" "NGINX installation failed. Check logs at ${INSTALL_LOG}"
                exit 1
            fi
            
            if [[ ! -f /etc/nginx/nginx.conf ]]; then
                log "ERROR" "NGINX installed but /etc/nginx/nginx.conf not found!"
                exit 1
            fi
            
            log "SUCCESS" "NGINX packages installed successfully."
        fi

        log "INFO" "Enabling and starting NGINX service..."
        systemctl enable nginx >> "${INSTALL_LOG}" 2>&1
        systemctl start nginx >> "${INSTALL_LOG}" 2>&1
        
        log "INFO" "Validating NGINX service status..."
        if systemctl is-active --quiet nginx; then
            log "SUCCESS" "NGINX service is active and running."
        else
            log "ERROR" "NGINX service failed to start!"
            echo -e "${RED}NGINX Systemctl Status:${NC}"
            systemctl status nginx --no-pager
            echo -e "${RED}NGINX Journal Logs (last 20 lines):${NC}"
            journalctl -u nginx -n 20 --no-pager
            exit 1
        fi
    fi
}

# --- MODSECURITY (LIBMODSECURITY) INSTALLATION ---
install_modsecurity_lib() {
    if confirm_step "ModSecurity Library (v3) Compilation"; then
        local src_dir="${TEMP_DIR}/ModSecurity"
        
        # 4. Source Reuse logic
        if [[ -d "${MODSEC_SRC_DIR}/.git" ]]; then
            log "INFO" "Found existing source at ${MODSEC_SRC_DIR}. Verifying version..."
            cd "${MODSEC_SRC_DIR}"
            local current_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
            if [[ "$current_tag" == "$MODSEC_VERSION" ]]; then
                log "INFO" "Correct version ${MODSEC_VERSION} found in ${MODSEC_SRC_DIR}. Reusing source."
                src_dir="${MODSEC_SRC_DIR}"
            else
                log "WARN" "Version mismatch (Found: ${current_tag}, Required: ${MODSEC_VERSION}). Using ${TEMP_DIR} instead."
                if [ -d "$src_dir" ]; then rm -rf "$src_dir"; fi
                git clone --depth 1 -b "$MODSEC_VERSION" https://github.com/SpiderLabs/ModSecurity "$src_dir" >> "${INSTALL_LOG}" 2>&1
            fi
        else
            log "INFO" "Cloning ModSecurity source (${MODSEC_VERSION})..."
            if [ -d "$src_dir" ]; then rm -rf "$src_dir"; fi
            git clone --depth 1 -b "$MODSEC_VERSION" https://github.com/SpiderLabs/ModSecurity "$src_dir" >> "${INSTALL_LOG}" 2>&1
        fi

        ACTIVE_MODSEC_SOURCE="$src_dir"
        cd "$ACTIVE_MODSEC_SOURCE"
        log "INFO" "Initializing submodules..."
        git submodule update --init --recursive >> "${INSTALL_LOG}" 2>&1
        
        log "INFO" "Building ModSecurity (Prefix: ${MODSEC_PREFIX})..."
        ./build.sh >> "${INSTALL_LOG}" 2>&1
        ./configure --prefix="${MODSEC_PREFIX}" >> "${INSTALL_LOG}" 2>&1
        make -j2 >> "${INSTALL_LOG}" 2>&1
        make install >> "${INSTALL_LOG}" 2>&1
        
        ldconfig
        
        log "INFO" "Verifying ModSecurity library installation..."
        if [[ ! -f "${MODSEC_PREFIX}/lib/libmodsecurity.so" ]]; then
            log "ERROR" "Verification failed: libmodsecurity.so not found in ${MODSEC_PREFIX}/lib."
            exit 1
        fi
        
        log "SUCCESS" "Libmodsecurity3 (${MODSEC_VERSION}) installed to ${MODSEC_PREFIX}."
    fi
}

# --- NGINX CONNECTOR COMPILATION ---
install_nginx_connector() {
    if confirm_step "NGINX ModSecurity Connector Compilation"; then
        # 12. Replace grep -oP usage with safer sed/awk parsing for compatibility.
        local nginx_v=$(nginx -v 2>&1 | sed 's/.*nginx\///' | awk '{print $1}')
        log "INFO" "Detected NGINX Version: ${nginx_v}"
        
        # 4. Extract existing nginx compile arguments for binary compatibility
        local nginx_args=$(nginx -V 2>&1 | sed -n -e 's/^.*configure arguments: //p')
        log "INFO" "Extracted NGINX Configure Arguments."
        
        cd "${TEMP_DIR}"
        log "INFO" "Downloading NGINX ${nginx_v} source for module compilation..."
        # 2. Replace all HTTP downloads with HTTPS
        wget -q "https://nginx.org/download/nginx-${nginx_v}.tar.gz" >> "${INSTALL_LOG}" 2>&1
        tar -xzvf "nginx-${nginx_v}.tar.gz" >> "${INSTALL_LOG}" 2>&1
        
        log "INFO" "Cloning Connector source..."
        if [ -d "ModSecurity-nginx" ]; then rm -rf ModSecurity-nginx; fi
        git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git >> "${INSTALL_LOG}" 2>&1
        
        cd "nginx-${nginx_v}"
        
        log "INFO" "Configuring NGINX with ModSecurity Connector (Binary Compatible mode)..."
        # Reuse existing configure flags and append the dynamic module
        eval ./configure --with-compat "$nginx_args" --add-dynamic-module=../ModSecurity-nginx >> "${INSTALL_LOG}" 2>&1
        make -j2 modules >> "${INSTALL_LOG}" 2>&1
        
        log "INFO" "Deploying dynamic module to ${NGINX_MOD_DIR}..."
        mkdir -p "${NGINX_MOD_DIR}"
        if [[ ! -f "objs/ngx_http_modsecurity_module.so" ]]; then
            log "ERROR" "Module compilation failed! ngx_http_modsecurity_module.so not found in objs/."
            exit 1
        fi
        cp objs/ngx_http_modsecurity_module.so "${NGINX_MOD_DIR}/"
        
        log "SUCCESS" "Connector module compiled and deployed to ${NGINX_MOD_DIR}/."
    fi
}


# --- OWASP CRS INSTALLATION ---
install_owasp_crs() {
    if confirm_step "OWASP Core Rule Set (CRS) Deployment"; then
        log "INFO" "Creating ModSec config directory..."
        mkdir -p /etc/nginx/modsec
        
        log "INFO" "Deploying base ModSecurity configuration from ${ACTIVE_MODSEC_SOURCE}..."
        cp "${ACTIVE_MODSEC_SOURCE}/modsecurity.conf-recommended" /etc/nginx/modsec/modsecurity.conf
        cp "${ACTIVE_MODSEC_SOURCE}/unicode.mapping" /etc/nginx/modsec/
        
        # 6. Apply Production ModSecurity Settings
        log "INFO" "Applying enterprise-safe production settings to modsecurity.conf..."
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
        sed -i 's/SecResponseBodyAccess On/SecResponseBodyAccess Off/' /etc/nginx/modsec/modsecurity.conf
        sed -i 's/SecAuditLogFormat Serial/SecAuditLogFormat JSON/' /etc/nginx/modsec/modsecurity.conf
        
        # Add performance and safety limits
        cat <<EOF >> /etc/nginx/modsec/modsecurity.conf
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000
EOF
        
        # 5. Audit Log Fix
        log "INFO" "Configuring ModSecurity audit logging to ${AUDIT_LOG_PATH}..."
        for param in "SecAuditEngine RelevantOnly" "SecAuditLog ${AUDIT_LOG_PATH}" "SecAuditLogParts ABIJDEFHZ"; do
            local key=$(echo $param | awk '{print $1}')
            if grep -q "^$key" /etc/nginx/modsec/modsecurity.conf; then
                sed -i "s|^$key.*|$param|" /etc/nginx/modsec/modsecurity.conf
            else
                echo "$param" >> /etc/nginx/modsec/modsecurity.conf
            fi
        done
        
        touch "${AUDIT_LOG_PATH}"
        chmod 640 "${AUDIT_LOG_PATH}"
        chown www-data:www-data "${AUDIT_LOG_PATH}"
        
        # Add logrotate configuration
        log "INFO" "Adding logrotate configuration for ModSecurity audit log..."
        cat <<EOF > /etc/logrotate.d/modsec
${AUDIT_LOG_PATH} {
    daily
    rotate 14
    missingok
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload nginx > /dev/null 2>/dev/null || true
    endscript
}
EOF

        log "INFO" "Cloning OWASP CRS to ${CRS_PATH}..."
        if [ -d "${CRS_PATH}" ]; then rm -rf "${CRS_PATH}"; fi
        git clone --depth 1 -b v4.1.0 https://github.com/coreruleset/coreruleset.git "${CRS_PATH}" >> "${INSTALL_LOG}" 2>&1
        
        log "INFO" "Configuring CRS with modular Enterprise Tuning..."
        cp "${CRS_PATH}/crs-setup.conf.example" "${CRS_PATH}/crs-setup.conf"
        
        # 7. Apply CRS Tuning via dedicated custom file (Safer than sed)
        mkdir -p /etc/nginx/modsec/custom-rules
        cat <<EOF > /etc/nginx/modsec/custom-rules/crs-tuning.conf
# Enterprise CRS Tuning
# Paranoia Level: 1
# Inbound Anomaly Score Threshold: 5
# Outbound Anomaly Score Threshold: 4

SecAction \
  "id:900000,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.paranoia_level=1,\
   setvar:tx.inbound_anomaly_score_threshold=5,\
   setvar:tx.outbound_anomaly_score_threshold=4"
EOF

        log "INFO" "Creating main.conf entry point with modular includes..."
        cat <<EOF > /etc/nginx/modsec/main.conf
Include /etc/nginx/modsec/modsecurity.conf
Include ${CRS_PATH}/crs-setup.conf
Include /etc/nginx/modsec/custom-rules/*.conf
Include ${CRS_PATH}/rules/*.conf
EOF

        log "SUCCESS" "OWASP CRS installed and tuned."
    fi
}

# --- NGINX CONFIGURATION ---
configure_nginx_waf() {
    if confirm_step "NGINX WAF Integration"; then
        create_backup "/etc/nginx" "nginx_config"
        
        # 8. Validate Module before configuration
        local module_path="${NGINX_MOD_DIR}/ngx_http_modsecurity_module.so"
        log "INFO" "Validating ModSecurity module existence at ${module_path}..."
        if [[ ! -f "$module_path" ]]; then
            log "ERROR" "CRITICAL: ModSecurity module binary not found at ${module_path}! Stopping safely."
            exit 1
        fi

        log "INFO" "Applying Smart Configuration for ModSecurity module..."
        local module_file="ngx_http_modsecurity_module.so"
        local new_load_line="load_module ${module_path};"
        
        # Check if the module is already loaded at ANY path
        if grep -q "$module_file" /etc/nginx/nginx.conf; then
            local existing_line=$(grep "$module_file" /etc/nginx/nginx.conf)
            if [[ "$existing_line" != *"$new_load_line"* ]]; then
                log "INFO" "Updating existing load_module path to ${NGINX_MOD_DIR}..."
                sed -i "s|load_module .*${module_file};|$new_load_line|" /etc/nginx/nginx.conf
            else
                log "INFO" "Module already correctly loaded at ${NGINX_MOD_DIR}."
            fi
        else
            log "INFO" "Adding load_module at the top of nginx.conf..."
            sed -i "1s|^|${new_load_line}\n|" /etc/nginx/nginx.conf
        fi
        
        # 5. Safer ModSecurity Enablement using conf.d
        log "INFO" "Enabling ModSecurity via /etc/nginx/conf.d/modsecurity.conf..."
        cat <<EOF > /etc/nginx/conf.d/modsecurity.conf
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
EOF

        log "INFO" "Applying performance tuning..."
        sed -i 's/worker_connections 768/worker_connections 4096/' /etc/nginx/nginx.conf || true
        
        log "INFO" "Validating NGINX syntax..."
        if nginx -t >> "${INSTALL_LOG}" 2>&1; then
            log "SUCCESS" "NGINX configuration validated."
            systemctl restart nginx
            systemctl enable nginx >> "${INSTALL_LOG}" 2>&1
            log "SUCCESS" "NGINX restarted and enabled successfully."
        else
            log "ERROR" "NGINX syntax error! Check logs."
            log "INFO" "Initiating automatic rollback..."
            local latest_backup=$(ls -t "${BACKUP_DIR}/nginx_config_"*.tar.gz | head -n 1)
            if [[ -n "$latest_backup" ]]; then
                rm -rf /etc/nginx
                tar -xzf "$latest_backup" -C /
                log "SUCCESS" "Rollback completed using ${latest_backup}."
                systemctl restart nginx
            else
                log "ERROR" "No backup found for rollback."
            fi
            exit 1
        fi
    fi
}


# --- SECURITY HARDENING ---
apply_hardening() {
    if confirm_step "Security Hardening (Headers/TLS)"; then
        log "INFO" "Applying global security headers..."
        cat <<EOF > /etc/nginx/conf.d/security_headers.conf
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
server_tokens off;
EOF
        if nginx -t >> "${INSTALL_LOG}" 2>&1; then
            systemctl reload nginx
            log "SUCCESS" "Hardening headers applied."
        else
            log "WARN" "Hardening configuration invalid, skipping reload."
        fi
    fi
}

# --- TESTING PHASE ---
run_waf_tests() {
    echo -e "\n${BLUE}=== WAF FUNCTIONAL TESTING & LOG VALIDATION ===${NC}"
    log "INFO" "Starting automated attack simulations..."
    
    local test_url="http://localhost"
    local total_tests=3
    local passed_tests=0
    
    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        log "WARN" "curl not found, skipping tests."
        return
    fi

    # 10. Verify Log Generation & CRS Triggers (Non-fatal)
    
    # Test 1: SQL Injection
    echo -n "Testing SQL Injection Blocking... "
    local sqli_res
    sqli_res=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}/?id=%27OR%201%3D1--" || echo "FAIL")
    if [[ "$sqli_res" == "403" ]]; then
        echo -e "${GREEN}PASS (403 Forbidden)${NC}"
        # Check Audit Log for SQLi trigger (if grep -q is safe under set -e)
        if grep -q "SQL Injection" "${AUDIT_LOG_PATH}" 2>/dev/null; then
            log "SUCCESS" "Log Validation: SQL Injection trigger found in audit log."
            passed_tests=$((passed_tests + 1))
        else
            log "WARN" "Log Validation: SQL Injection blocked but trigger NOT found in ${AUDIT_LOG_PATH}."
        fi
    else
        echo -e "${RED}FAIL ($sqli_res)${NC}"
    fi
    
    # Test 2: XSS
    echo -n "Testing XSS Blocking... "
    local xss_res
    xss_res=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}/?q=%3Cscript%3Ealert(1)%3C/script%3E" || echo "FAIL")
    if [[ "$xss_res" == "403" ]]; then
        echo -e "${GREEN}PASS (403 Forbidden)${NC}"
        # Check Audit Log for XSS trigger
        if grep -q "XSS" "${AUDIT_LOG_PATH}" 2>/dev/null; then
            log "SUCCESS" "Log Validation: XSS trigger found in audit log."
            passed_tests=$((passed_tests + 1))
        else
            log "WARN" "Log Validation: XSS blocked but trigger NOT found in ${AUDIT_LOG_PATH}."
        fi
    else
        echo -e "${RED}FAIL ($xss_res)${NC}"
    fi

    # Test 3: LFI
    echo -n "Testing LFI Blocking... "
    local lfi_res
    lfi_res=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}/?file=%2E%2E/%2E%2E/etc/passwd" || echo "FAIL")
    if [[ "$lfi_res" == "403" ]]; then
        echo -e "${GREEN}PASS (403 Forbidden)${NC}"
        # Check Audit Log for LFI/Path Traversal trigger
        if grep -E -q "path traversal|etc/passwd" "${AUDIT_LOG_PATH}" 2>/dev/null; then
            log "SUCCESS" "Log Validation: LFI trigger found in audit log."
            passed_tests=$((passed_tests + 1))
        else
            log "WARN" "Log Validation: LFI blocked but trigger NOT found in ${AUDIT_LOG_PATH}."
        fi
    else
        echo -e "${RED}FAIL ($lfi_res)${NC}"
    fi
    
    if [[ $passed_tests -eq $total_tests ]]; then
        log "SUCCESS" "WAF testing and log validation: ALL PASS ($passed_tests/$total_tests)"
    else
        log "WARN" "WAF testing and log validation: PARTIAL FAIL ($passed_tests/$total_tests)"
    fi
}

# --- MAIN EXECUTION ---
main() {
    show_banner
    check_prerequisites
    
    install_dependencies
    install_nginx
    install_modsecurity_lib
    install_nginx_connector
    install_owasp_crs
    configure_nginx_waf
    apply_hardening
    
    run_waf_tests
    
    # 9. Improved Health Checks (Non-fatal)
    log "INFO" "Running enhanced enterprise health checks..."
    
    # Verify ModSecurity configuration in active NGINX state
    # Using 'if command; then' which is safe under set -e
    if nginx -T 2>/dev/null | grep -qi "modsecurity on"; then
        log "SUCCESS" "Health Check: ModSecurity is actively enabled in NGINX configuration."
    else
        log "ERROR" "Health Check: ModSecurity is NOT detected in active NGINX configuration!"
    fi

    # Verify Module Initialized
    local error_log
    error_log=$(nginx -V 2>&1 | sed -n 's/.*--error-log-path=\([^ ]*\).*/\1/p' || echo "/var/log/nginx/error.log")
    if [[ -f "$error_log" ]] && grep -qi "ModSecurity-nginx" "$error_log" 2>/dev/null; then
        log "SUCCESS" "Health Check: ModSecurity-nginx module initialized successfully."
    else
        log "WARN" "Health Check: 'ModSecurity-nginx' initialization message not found or log missing."
    fi

    # Connectivity Check
    if curl -I http://localhost >> "${INSTALL_LOG}" 2>&1; then
        log "SUCCESS" "Health Check: NGINX is responding to requests."
    else
        log "WARN" "Health Check: NGINX failed to respond to localhost."
    fi
    
    cleanup
    
    echo -e "\n${GREEN}############################################################${NC}"
    echo -e "${GREEN}#          WAF DEPLOYMENT COMPLETED SUCCESSFULLY           #${NC}"
    echo -e "${GREEN}############################################################${NC}"
    log "SUCCESS" "Installation finished."
}

main "$@"
