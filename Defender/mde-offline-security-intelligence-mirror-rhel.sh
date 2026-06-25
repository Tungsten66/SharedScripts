#!/usr/bin/env bash
# =============================================================================
# LEGAL DISCLAIMER
# This Sample Code is provided for the purpose of illustration only and is not
# intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
# RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
# nonexclusive, royalty-free right to use and modify the Sample Code and to
# reproduce and distribute the object code form of the Sample Code, provided
# that You agree: (i) to not use Our name, logo, or trademarks to market Your
# software product in which the Sample Code is embedded; (ii) to include a valid
# copyright notice on Your software product in which the Sample Code is embedded;
# and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
# against any claims or lawsuits, including attorneys' fees, that arise or result
# from the use or distribution of the Sample Code.
#
# This posting is provided "AS IS" with no warranties, and confers no rights.
# Use of included script samples are subject to the terms specified at
# https://www.microsoft.com/en-us/legal/copyright
# =============================================================================
#
# .SYNOPSIS
#     Configures a RHEL 8.x / 9.x server as a Microsoft Defender for Endpoint
#     (MDE) offline security intelligence mirror server.
#
# .DESCRIPTION
#     This script automates the full setup of an MDE offline signature mirror
#     as documented at:
#     https://learn.microsoft.com/en-us/defender-endpoint/linux-support-offline-security-intelligence-update?tabs=portal
#
#     The server fulfills two roles simultaneously:
#       1. Mirror server — clones the Microsoft mdatp-xplat downloader repo,
#          downloads Linux signature packages from Microsoft on a cron schedule,
#          and hosts them via nginx so MDE Linux endpoints can pull updates
#          without direct internet access.
#       2. MDE endpoint — configured via Defender/Intune Security Settings
#          Management policy to pull its own updates from the local mirror.
#
#     Components installed/configured:
#       - git, nginx (AppStream module-aware for RHEL 8)
#       - Dedicated service account (mdatp-mirror) for least-privilege operation
#       - Microsoft xplat_offline_updates_download.sh + settings.json
#       - Hardened nginx virtual host (method restriction, no server tokens)
#       - SELinux context (httpd_sys_content_t) on the web root
#       - firewalld HTTP rule
#       - /etc/cron.d job (every 8 hours, runs as mdatp-mirror)
#       - logrotate configuration
#
# .INPUTS
#     --mode       Required. Either 'lab' or 'production'.
#
#     Lab mode (--mode lab):
#       HTTP only, firewall open to all interfaces, 3 GB disk check.
#       No additional parameters required.
#
#     Production mode (--mode production):
#       HTTPS, subnet-scoped firewall, 8 GB disk check.
#       Requires:
#         --hostname   FQDN or internal hostname of this server (must match TLS cert CN)
#         --subnet     CIDR subnet of MDE endpoints (e.g. 10.0.1.0/24)
#         --cert       Path to TLS certificate file (from your internal CA)
#         --key        Path to TLS private key file
#
# .OUTPUTS
#     On success, prints the mirror URL and Defender portal policy settings
#     required to point MDE Linux endpoints at this mirror server.
#
#     Logs:
#       /var/log/mdatp-offline-update/downloader.log  — signature downloader
#       /var/log/mdatp-offline-update/cron.log         — cron stdout/stderr
#       /var/log/nginx/wdav-update-access.log          — nginx access log
#       /var/log/nginx/wdav-update-error.log           — nginx error log
#
# .PORTAL CONFIGURATION
#     After running this script, configure the MDE endpoints via the Defender
#     portal using the Security Settings Management policy. Follow the steps
#     under "Configure the endpoints > Portal" in the Microsoft documentation:
#     https://learn.microsoft.com/en-us/defender-endpoint/linux-support-offline-security-intelligence-update?tabs=portal#configure-the-endpoints
#
#     The mirror URL to enter in the policy is printed at the end of this script.
#     Key settings:
#       - Enable offline security intelligence update:        Enabled
#       - Offline security intelligence update URL:           <printed by script>
#       - Offline security intelligence update fallback to cloud: False
#       - Security intelligence update time interval (sec):  28800
#       - Automated security intelligence updates:           Enabled (required)
#
# .VERIFICATION
#     After the Defender portal policy applies to the endpoint, verify with:
#
#       mdatp health --details definitions
#
#     Success looks like:
#       automatic_definition_update_enabled         : true [managed]
#       definitions_status                          : "up_to_date"
#       offline_definition_update                   : "enabled" [managed]
#       offline_definition_url_configured           : "http://<mirror-IP>/linux/production/" [managed]
#       offline_definition_update_fallback_to_cloud : false [managed]
#       offline_definition_update_verify_sig        : "enabled"
#
#     To trigger a manual update from the mirror:
#       mdatp definitions update
#
#     To confirm the update sourced from the mirror (not Microsoft cloud):
#       mdatp health --field definitions_update_source_uri
#     Expected: your mirror URL, not https://mdav.us.endpoint.security.microsoft.com/...
#
# .NOTES
#     Name: mde-offline-security-intelligence-mirror-rhel.sh
#     Authors/Contributors: Nick OConnor
#     DateCreated: 2026-06-24
#     Revisions:
#       2026-06-24 — Initial version
#       2026-06-24 — Fixed nginx limit_except placement (must be inside location block, not server block)
#       2026-06-24 — Removed default_server from nginx listen directive (conflicts with RHEL 8/9 default nginx.conf)
#       2026-06-24 — Replaced static CONFIGURATION section with --mode lab|production argument parsing
#       2026-06-25 — Fixed nginx 404: strip default_server from nginx.conf, chmod 755 on download dir, reapply SELinux context in cron
#       2026-06-25 — Replaced chcon with semanage fcontext for permanent SELinux context (new files inherit automatically)
#
# =============================================================================
# mde-offline-mirror-setup.sh
#
# Sets up a Microsoft Defender for Endpoint (MDE) offline security intelligence
# mirror server on RHEL 8.x / 9.x.
#
# This server:
#   - Downloads MDE signature updates from Microsoft on a schedule
#   - Hosts those signatures via nginx so MDE Linux endpoints can pull from it
#   - Also acts as an MDE endpoint itself (pulls from localhost mirror)
#
# Reference:
#   This script implements the offline security intelligence update mirror
#   architecture described in the Microsoft Defender for Endpoint documentation:
#   https://learn.microsoft.com/en-us/defender-endpoint/linux-support-offline-security-intelligence-update?tabs=portal
#
#   Specifically, this covers:
#   - Configuring the mirror server (HTTP host + downloader script + cron)
#   - Hosting the offline security intelligence updates on the mirror server
#   - The endpoint configuration values to apply via Security Settings Management
#     in the Defender/Intune portal (printed at the end of this script)
#
# Usage:
#   Step 1 — Download the script to the target RHEL server:
#     curl -fsSL https://raw.githubusercontent.com/Tungsten66/SharedScripts/refs/heads/main/Defender/mde-offline-security-intelligence-mirror-rhel.sh \
#       -o /tmp/mde-offline-security-intelligence-mirror-rhel.sh
#
#   Step 2 — Run the script as root with the appropriate mode:
#
#     Lab:
#       sudo bash /tmp/mde-offline-security-intelligence-mirror-rhel.sh --mode lab
#
#     Production:
#       sudo bash /tmp/mde-offline-security-intelligence-mirror-rhel.sh --mode production \
#         --hostname mde-mirror.yourdomain.internal \
#         --subnet 10.0.1.0/24 \
#         --cert /etc/nginx/ssl/wdav.crt \
#         --key /etc/nginx/ssl/wdav.key
#
#   Prerequisites before running:
#     - RHEL 8.x or 9.x
#     - Outbound internet access to github.com and go.microsoft.com
#     - A dedicated data disk mounted at /opt/wdav-update with >= 3 GB free
#       (a 4 GiB Azure data disk formatted with XFS is sufficient for lab)
#     - MDE (mdatp) already installed at version >= 101.24022.0001
#     - Production mode: TLS cert/key from your internal CA placed on the server
#
#   Do NOT pipe directly from curl | bash — download first, then run.
# =============================================================================

# -----------------------------------------------------------------------------
# SOURCING GUARD
# If someone accidentally runs "source mde-offline-mirror-setup.sh" or
# ". mde-offline-mirror-setup.sh", exit 1 would kill their shell session.
# This guard detects sourcing and returns instead of exiting, keeping the
# shell alive while still aborting the script.
# -----------------------------------------------------------------------------
if [[ -n "${BASH_SOURCE[0]}" && "${BASH_SOURCE[0]}" != "${0}" ]]; then
    echo "ERROR: Do not source this script. Run it directly:"
    echo "  bash $(basename "${BASH_SOURCE[0]}")"
    return 1
fi

set -euo pipefail

# =============================================================================
# FIXED CONFIGURATION — paths that do not change between modes
# =============================================================================

REPO_URL="https://github.com/microsoft/mdatp-xplat.git"
REPO_DIR="/opt/mdatp-xplat"
DOWNLOAD_DIR="/opt/wdav-update"
DOWNLOADER_LOG="/var/log/mdatp-offline-update/downloader.log"
CRON_LOG="/var/log/mdatp-offline-update/cron.log"
MIRROR_USER="mdatp-mirror"
NGINX_CONF="/etc/nginx/conf.d/wdav-update.conf"
CRON_FILE="/etc/cron.d/mdatp-mirror"
LOGROTATE_CONF="/etc/logrotate.d/mdatp-mirror"

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

usage() {
    echo ""
    echo "Usage:"
    echo "  Lab:"
    echo "    sudo bash $(basename "$0") --mode lab"
    echo ""
    echo "  Production:"
    echo "    sudo bash $(basename "$0") --mode production \\"
    echo "      --hostname mde-mirror.yourdomain.internal \\"
    echo "      --subnet 10.0.1.0/24 \\"
    echo "      --cert /etc/nginx/ssl/wdav.crt \\"
    echo "      --key /etc/nginx/ssl/wdav.key"
    echo ""
    exit 1
}

MODE=""
SERVER_NAME="_"
FIREWALL_SOURCE_SUBNET=""
ENABLE_HTTPS=false
TLS_CERT="/etc/nginx/ssl/wdav-update.crt"
TLS_KEY="/etc/nginx/ssl/wdav-update.key"
CRON_SCHEDULE="0 */8 * * *"   # Microsoft default: every 8 hours

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)        MODE="$2";                   shift 2 ;;
        --hostname)    SERVER_NAME="$2";             shift 2 ;;
        --subnet)      FIREWALL_SOURCE_SUBNET="$2";  shift 2 ;;
        --cert)        TLS_CERT="$2";                shift 2 ;;
        --key)         TLS_KEY="$2";                 shift 2 ;;
        --cron)        CRON_SCHEDULE="$2";           shift 2 ;;
        -h|--help)     usage ;;
        *)             echo "Unknown option: $1"; usage ;;
    esac
done

# Validate mode
if [[ -z "$MODE" ]]; then
    echo "ERROR: --mode is required (lab or production)"
    usage
fi

if [[ "$MODE" == "lab" ]]; then
    ENABLE_HTTPS=false
    REQUIRED_KB=$(( 3 * 1024 * 1024 ))   # 3 GB — sufficient for a 4 GiB XFS disk
    echo ""
    echo "  Mode: LAB"
    echo "  Transport: HTTP (port 80, open to all interfaces)"
    echo "  Disk check: 3 GB"
    echo "  Firewall: open to all"
    echo ""

elif [[ "$MODE" == "production" ]]; then
    ENABLE_HTTPS=true
    REQUIRED_KB=$(( 8 * 1024 * 1024 ))   # 8 GB — production disk headroom

    # Production requires all four additional parameters
    PROD_ERRORS=()
    [[ "$SERVER_NAME" == "_" ]]              && PROD_ERRORS+=("--hostname is required in production mode")
    [[ -z "$FIREWALL_SOURCE_SUBNET" ]]       && PROD_ERRORS+=("--subnet is required in production mode")
    [[ ! -f "$TLS_CERT" ]]                   && PROD_ERRORS+=("--cert file not found: ${TLS_CERT}")
    [[ ! -f "$TLS_KEY" ]]                    && PROD_ERRORS+=("--key file not found: ${TLS_KEY}")

    if [[ ${#PROD_ERRORS[@]} -gt 0 ]]; then
        echo "ERROR: Production mode is missing required parameters:"
        for e in "${PROD_ERRORS[@]}"; do echo "  - $e"; done
        usage
    fi

    echo ""
    echo "  Mode: PRODUCTION"
    echo "  Transport: HTTPS (port 443)"
    echo "  Hostname:  ${SERVER_NAME}"
    echo "  Subnet:    ${FIREWALL_SOURCE_SUBNET}"
    echo "  Cert:      ${TLS_CERT}"
    echo "  Key:       ${TLS_KEY}"
    echo "  Disk check: 8 GB"
    echo ""
else
    echo "ERROR: --mode must be 'lab' or 'production', got: ${MODE}"
    usage
fi

# =============================================================================
# HELPERS
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# =============================================================================
# PHASE 0 — PREFLIGHT CHECKS
# =============================================================================

info "Phase 0: Preflight checks"

# --- Must be root ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root. Use: sudo bash $(basename "$0")"
fi

# --- RHEL version check ---
if [[ ! -f /etc/redhat-release ]]; then
    error "This script targets RHEL 8.x / 9.x. /etc/redhat-release not found."
fi

RHEL_VERSION=$(rpm -q --queryformat '%{VERSION}' redhat-release 2>/dev/null | cut -d. -f1)
if [[ "$RHEL_VERSION" != "8" && "$RHEL_VERSION" != "9" ]]; then
    error "Unsupported RHEL major version: ${RHEL_VERSION}. Expected 8 or 9."
fi
success "RHEL ${RHEL_VERSION} detected"

# --- Internet connectivity to required Microsoft URLs ---
info "Checking connectivity to required URLs..."
for url in "https://github.com" "https://go.microsoft.com"; do
    if ! curl -sf --max-time 10 --head "$url" -o /dev/null; then
        error "Cannot reach ${url}. This server requires outbound internet access to download signatures."
    fi
done
success "Internet connectivity verified"

# --- Disk space check on the download directory partition ---
# The download directory may not exist yet; check the nearest existing parent.
CHECK_PATH="$DOWNLOAD_DIR"
while [[ ! -d "$CHECK_PATH" ]]; do
    CHECK_PATH=$(dirname "$CHECK_PATH")
done

AVAILABLE_KB=$(df --output=avail "$CHECK_PATH" | tail -1)
if [[ "$AVAILABLE_KB" -lt "$REQUIRED_KB" ]]; then
    AVAIL_GB=$(( AVAILABLE_KB / 1024 / 1024 ))
    error "Insufficient disk space on partition containing ${DOWNLOAD_DIR}. Required: 4 GB, Available: ${AVAIL_GB} GB. Mount a dedicated data disk to ${DOWNLOAD_DIR} before running this script."
fi
success "Disk space OK ($(( AVAILABLE_KB / 1024 / 1024 )) GB available)"

# =============================================================================
# PHASE 1 — CREATE DEDICATED SERVICE ACCOUNT
# =============================================================================

info "Phase 1: Creating service account '${MIRROR_USER}'"

if id "$MIRROR_USER" &>/dev/null; then
    warn "Service account '${MIRROR_USER}' already exists — skipping creation"
else
    useradd \
        --system \
        --shell /sbin/nologin \
        --home-dir "$DOWNLOAD_DIR" \
        --no-create-home \
        --comment "MDE offline mirror service account" \
        "$MIRROR_USER"
    success "Service account '${MIRROR_USER}' created"
fi

# =============================================================================
# PHASE 2 — INSTALL DEPENDENCIES
# =============================================================================

info "Phase 2: Installing dependencies (git, nginx)"

# On RHEL 8, nginx is delivered via an AppStream module.
# On RHEL 9, it is available directly in AppStream without module enable.
if [[ "$RHEL_VERSION" == "8" ]]; then
    dnf module enable -y nginx:mainline &>/dev/null || true
fi

dnf install -y git nginx &>/dev/null
success "git and nginx installed"

# Remove 'default_server' from the RHEL default nginx.conf server block.
# RHEL ships nginx.conf with 'listen 80 default_server' which conflicts with
# our vhost — nginx will ignore our vhost and serve from /usr/share/nginx/html,
# returning 404 for all requests to /opt/wdav-update. Stripping default_server
# lets our vhost in conf.d/ win the request routing.
if grep -q "default_server" /etc/nginx/nginx.conf; then
    sed -i 's/listen       80 default_server;/listen       80;/' /etc/nginx/nginx.conf
    sed -i 's/listen       \[::\]:80 default_server;/listen       [::]:80;/' /etc/nginx/nginx.conf
    info "Removed default_server from /etc/nginx/nginx.conf"
fi

# =============================================================================
# PHASE 3 — CLONE / UPDATE MICROSOFT DOWNLOADER REPO
# =============================================================================

info "Phase 3: Cloning/updating microsoft/mdatp-xplat repo"

if [[ -d "${REPO_DIR}/.git" ]]; then
    warn "Repo already exists at ${REPO_DIR} — pulling latest"
    sudo -u "$MIRROR_USER" git -C "$REPO_DIR" pull -q
    success "Repo updated"
else
    git clone "$REPO_URL" "$REPO_DIR" -q
    chown -R "${MIRROR_USER}:${MIRROR_USER}" "$REPO_DIR"
    success "Repo cloned to ${REPO_DIR}"
fi

SCRIPT_PATH="${REPO_DIR}/linux/definition_downloader/xplat_offline_updates_download.sh"
SETTINGS_PATH="${REPO_DIR}/linux/definition_downloader/settings.json"

if [[ ! -f "$SCRIPT_PATH" ]]; then
    error "Downloader script not found at ${SCRIPT_PATH}. Check the repo structure."
fi

chmod +x "$SCRIPT_PATH"

# =============================================================================
# PHASE 4 — CONFIGURE settings.json
# =============================================================================

info "Phase 4: Writing settings.json"

# downloadMacUpdates is set to false — this is a Linux-only mirror.
# downloadPreviewUpdates is false — production endpoints should receive
#   stable (GA) definitions only, not preview builds.
# backupPreviousUpdates is true — retains the previous (n-1) signature set in
#   a _back/ subdirectory. This allows rollback if a new signature causes issues.
cat > "$SETTINGS_PATH" <<EOF
{
  "downloadFolder": "${DOWNLOAD_DIR}",
  "downloadLinuxUpdates": true,
  "downloadMacUpdates": false,
  "downloadPreviewUpdates": false,
  "backupPreviousUpdates": true,
  "logFilePath": "${DOWNLOADER_LOG}"
}
EOF

success "settings.json configured"

# =============================================================================
# PHASE 5 — CREATE DIRECTORIES AND SET PERMISSIONS
# =============================================================================

info "Phase 5: Creating directories and setting permissions"

LOG_DIR=$(dirname "$DOWNLOADER_LOG")

mkdir -p "$DOWNLOAD_DIR" "$LOG_DIR"

# nginx needs read access to the download directory to serve files.
# 755 allows the nginx user (not in mdatp-mirror group) to traverse and read.
# SELinux context httpd_sys_content_t is also required — applied in Phase 7.
chown -R "${MIRROR_USER}:nginx" "$DOWNLOAD_DIR"
chmod -R 755 "$DOWNLOAD_DIR"

chown -R "${MIRROR_USER}:${MIRROR_USER}" "$LOG_DIR"
chmod 750 "$LOG_DIR"

success "Directories created and permissions set"

# =============================================================================
# PHASE 6 — CONFIGURE NGINX
# =============================================================================

info "Phase 6: Configuring nginx"

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY NOTE — HTTP (port 80) is used here for lab/testing purposes only.
#
# In production, this server SHOULD be configured with HTTPS (port 443) using
# a certificate issued by your organization's internal Certificate Authority (CA).
# Using HTTPS ensures:
#   - Transport-layer encryption of signature packages in transit
#   - Protection against man-in-the-middle (MITM) inspection or spoofing
#   - Compliance with organizational TLS policy (e.g., NIST SP 800-52 Rev 2,
#     CIS Benchmark for nginx, and Microsoft's own secure communications guidance)
#
# Note: MDE always cryptographically verifies the signature of downloaded update
# packages regardless of transport protocol, so the payload cannot be tampered
# with over HTTP. However, HTTP does not protect the connection itself.
#
# To switch to HTTPS: set ENABLE_HTTPS=true in the CONFIGURATION section at
# the top of this script, provide your cert/key paths, and re-run.
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$ENABLE_HTTPS" == "true" ]]; then
    if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
        error "ENABLE_HTTPS=true but cert/key not found at ${TLS_CERT} / ${TLS_KEY}. Provide a cert from your internal CA before enabling HTTPS."
    fi
    mkdir -p /etc/nginx/ssl
    cat > "$NGINX_CONF" <<NGINXCONF
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     ${TLS_CERT};
    ssl_certificate_key ${TLS_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    root ${DOWNLOAD_DIR};
    autoindex on;
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    location /linux/production/ {
        limit_except GET HEAD { deny all; }
    }
    location / {
        limit_except GET HEAD { deny all; }
    }

    access_log /var/log/nginx/wdav-update-access.log;
    error_log  /var/log/nginx/wdav-update-error.log;
}
NGINXCONF
else
    cat > "$NGINX_CONF" <<NGINXCONF
server {
    # HTTP for testing only — set ENABLE_HTTPS=true in the CONFIGURATION
    # section at the top of this script to switch to HTTPS for production.
    # Note: 'default_server' is omitted because RHEL 8/9's default nginx.conf
    # already declares a default_server on port 80.
    listen 80;
    server_name _;

    root ${DOWNLOAD_DIR};
    autoindex on;
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # MDE endpoints request: http://<mirror-IP>/linux/production/
    location /linux/production/ {
        # Restrict to read-only HTTP methods — static file mirror only.
        limit_except GET HEAD {
            deny all;
        }
    }

    location / {
        limit_except GET HEAD {
            deny all;
        }
    }

    access_log /var/log/nginx/wdav-update-access.log;
    error_log  /var/log/nginx/wdav-update-error.log;
}
NGINXCONF
fi

# Test nginx config before enabling
nginx -t 2>/dev/null || error "nginx configuration test failed. Check ${NGINX_CONF}."
success "nginx configured and config test passed"

# =============================================================================
# PHASE 7 — SELINUX CONTEXTS
# =============================================================================

info "Phase 7: Applying SELinux contexts"

if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
    # Install policycoreutils-python-utils if needed (provides semanage)
    if ! command -v semanage &>/dev/null; then
        dnf install -y policycoreutils-python-utils &>/dev/null
    fi

    # Set a permanent default file context so ALL future files created under
    # DOWNLOAD_DIR (by the cron downloader) automatically get httpd_sys_content_t.
    # This is the correct production approach — chcon only relabels existing files
    # and does not persist for new files created after each signature download.
    semanage fcontext -a -t httpd_sys_content_t "${DOWNLOAD_DIR}(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t httpd_sys_content_t "${DOWNLOAD_DIR}(/.*)?"

    # Apply the policy to existing files now
    restorecon -R "$DOWNLOAD_DIR"

    # nginx does not need outbound network connections — only serves files.
    # Turning this off limits what nginx can do if compromised.
    setsebool -P httpd_can_network_connect off

    success "SELinux permanent context policy set (httpd_sys_content_t) — new files will inherit automatically"
else
    warn "SELinux is disabled or not present — skipping context changes"
fi

# =============================================================================
# PHASE 8 — FIREWALLD
# =============================================================================

info "Phase 8: Configuring firewalld"

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY NOTE — Port 80 is opened to ALL source addresses on all interfaces.
#
# In production, this rule SHOULD be scoped to the specific subnet(s) that
# contain your MDE-managed Linux endpoints. For example:
#
#   firewall-cmd --permanent --zone=internal --add-source=10.0.1.0/24
#   firewall-cmd --permanent --zone=internal --add-service=http
#
# Restricting to a source subnet prevents any host outside your network from
# reaching the mirror, limiting exposure if port 80 were ever unintentionally
# reachable from outside the environment.
# ─────────────────────────────────────────────────────────────────────────────

if systemctl is-active --quiet firewalld; then
    if [[ -n "$FIREWALL_SOURCE_SUBNET" ]]; then
        # Production: scope access to the MDE endpoint subnet only.
        # This prevents any host outside the specified subnet from reaching the mirror.
        firewall-cmd --permanent --zone=internal --add-source="$FIREWALL_SOURCE_SUBNET" &>/dev/null
        if [[ "$ENABLE_HTTPS" == "true" ]]; then
            firewall-cmd --permanent --zone=internal --add-service=https &>/dev/null
            firewall-cmd --permanent --zone=internal --add-service=http &>/dev/null  # for 80→443 redirect
        else
            firewall-cmd --permanent --zone=internal --add-service=http &>/dev/null
        fi
        firewall-cmd --reload &>/dev/null
        success "firewalld: access restricted to subnet ${FIREWALL_SOURCE_SUBNET}"
    else
        # ─────────────────────────────────────────────────────────────────────
        # SECURITY NOTE — Port 80 is opened to ALL source addresses (lab mode).
        # In production, pass --subnet <CIDR> to restrict access to only the
        # subnet containing your MDE-managed Linux endpoints.
        # ─────────────────────────────────────────────────────────────────────
        if [[ "$ENABLE_HTTPS" == "true" ]]; then
            firewall-cmd --permanent --add-service=https &>/dev/null
            firewall-cmd --permanent --add-service=http &>/dev/null  # for 80→443 redirect
        else
            firewall-cmd --permanent --add-service=http &>/dev/null
        fi
        firewall-cmd --reload &>/dev/null
        success "firewalld: HTTP/HTTPS opened on all interfaces (lab mode)"
    fi
else
    warn "firewalld is not running — skipping firewall configuration"
fi

# =============================================================================
# PHASE 9 — LOG ROTATION
# =============================================================================

info "Phase 9: Configuring log rotation"

cat > "$LOGROTATE_CONF" <<EOF
${LOG_DIR}/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 640 ${MIRROR_USER} ${MIRROR_USER}
}
EOF

success "Log rotation configured (weekly, 4 weeks retained)"

# =============================================================================
# PHASE 10 — ENABLE AND START NGINX
# =============================================================================

info "Phase 10: Enabling and starting nginx"

systemctl enable --now nginx &>/dev/null
success "nginx enabled and started"

# =============================================================================
# PHASE 11 — INITIAL SIGNATURE DOWNLOAD
# =============================================================================

info "Phase 11: Running initial signature download (this may take several minutes)"

# Run as the service account so all downloaded files are owned by mdatp-mirror.
# The service account has no login shell, so we use sudo -u with explicit bash.
sudo -u "$MIRROR_USER" bash "$SCRIPT_PATH"

success "Initial signature download complete"

# =============================================================================
# PHASE 12 — CRON JOB
# =============================================================================

info "Phase 12: Installing cron job"

# Runs every 8 hours (Microsoft default update interval).
# Does a git pull first to keep the downloader script itself current,
# then runs the download script as the mdatp-mirror service account.
cat > "$CRON_FILE" <<EOF
# MDE offline security intelligence mirror — updates on schedule: ${CRON_SCHEDULE}
# Matches the default endpoint pull interval (definitionUpdatesInterval: 28800s).
# Override schedule at runtime with --cron "0 */4 * * *" if needed.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

${CRON_SCHEDULE}  ${MIRROR_USER}  cd ${REPO_DIR} && git pull -q || echo "WARNING: git pull failed, using existing script" && bash ${SCRIPT_PATH} >> ${CRON_LOG} 2>&1 && chmod -R 755 ${DOWNLOAD_DIR} && restorecon -R ${DOWNLOAD_DIR}
EOF

chmod 644 "$CRON_FILE"
success "Cron job installed at ${CRON_FILE}"

# =============================================================================
# PHASE 13 — VERIFY
# =============================================================================

info "Phase 13: Verification"

# nginx running?
if systemctl is-active --quiet nginx; then
    success "nginx is running"
else
    error "nginx failed to start. Check: journalctl -u nginx"
fi

# Signature files present?
if find "$DOWNLOAD_DIR" -name "updates.zip" | grep -q .; then
    success "Signature files downloaded:"
    find "$DOWNLOAD_DIR" -name "updates.zip" | while read -r f; do
        echo "    $f ($(du -sh "$f" | cut -f1))"
    done
else
    warn "No updates.zip found under ${DOWNLOAD_DIR} — download may have failed. Check: ${DOWNLOADER_LOG}"
fi

# =============================================================================
# DONE — PRINT NEXT STEPS
# =============================================================================

SERVER_IP=$(hostname -I | awk '{print $1}')
PROTOCOL="http"
[[ "$ENABLE_HTTPS" == "true" ]] && PROTOCOL="https"
MIRROR_URL="${PROTOCOL}://${SERVER_IP}/linux/production/"
[[ "$SERVER_NAME" != "_" ]] && MIRROR_URL="${PROTOCOL}://${SERVER_NAME}/linux/production/"

echo ""
echo "============================================================"
echo " MDE Offline Mirror Setup Complete (mode: ${MODE})"
echo "============================================================"
echo ""
echo " Mirror URL (use this in Defender portal policy):"
echo "   ${MIRROR_URL}"
echo ""
echo " NEXT STEPS — Defender Portal:"
echo "   Endpoints > Configuration management > Endpoint security policies"
echo "   > Create new policy > Linux > Microsoft Defender Antivirus"
echo ""
echo "   Setting                                   Value"
echo "   ─────────────────────────────────────────────────────────"
echo "   Enable offline security intelligence      true"
echo "   Offline update URL or directory           ${MIRROR_URL}"
echo "   Fallback to cloud                         false"
echo "   Update time interval (seconds)            28800"
echo "   Automated security intelligence updates   true (required)"
echo ""
echo " Verify on endpoints after policy applies:"
echo "   mdatp health --details definitions"
echo "   mdatp definitions update"
echo ""
echo " Logs:"
echo "   Downloader: ${DOWNLOADER_LOG}"
echo "   Cron:       ${CRON_LOG}"
echo "   nginx:      /var/log/nginx/wdav-update-access.log"
echo "============================================================"
