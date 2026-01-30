#!/bin/bash
#===============================================================================
# Script Name:  schedule_mdatp_scan.sh
# Description:  Schedules a weekly Microsoft Defender for Endpoint antivirus scan
#               on Linux using crontab. The scan runs every Sunday at a randomly
#               generated time (chosen once when the script runs).
#
# Features:
#   - Generates random hour (0-11) and minute (0-59) for scan time
#   - Idempotent: safe to run multiple times without creating duplicates
#   - Preserves existing crontab entries
#   - Uses a unique marker comment to identify and update the MDATP scan entry
#
# Reference:
#   https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scan-crontab
#
# Usage:
#   chmod +x schedule_mdatp_scan.sh
#   sudo ./schedule_mdatp_scan.sh
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------

# Unique marker comment to identify the MDATP weekly scan cron entry.
# This allows the script to find and update/replace the entry idempotently.
readonly CRON_MARKER="# MDATP_WEEKLY_SCAN"

# Path to the Microsoft Defender for Endpoint scan command (per Microsoft Learn docs)
readonly MDATP_CMD="/usr/bin/mdatp"

# Scan type: "quick" or "full" (quick is recommended for weekly scheduled scans)
readonly SCAN_TYPE="full"

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------

# Print an informational message
log_info() {
    echo "[INFO] $1"
}

# Print an error message and exit
log_error() {
    echo "[ERROR] $1" >&2
    exit 1
}

# Check if running as root (required to modify root's crontab)
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
    fi
}

# Check if the mdatp command exists and is executable
check_mdatp_installed() {
    if [[ ! -x "$MDATP_CMD" ]]; then
        log_error "Microsoft Defender for Endpoint (mdatp) is not installed or not found at $MDATP_CMD"
    fi
    log_info "Found mdatp at $MDATP_CMD"
}

# Generate a random hour (0-11) using $RANDOM
generate_random_hour() {
    # $RANDOM returns a value between 0 and 32767
    # Modulo 12 gives us a value between 0 and 11 (first 12 hours of the day)
    echo $(( RANDOM % 12 ))
}

# Generate a random minute (0-59) using $RANDOM
generate_random_minute() {
    # Modulo 60 gives us a value between 0 and 59
    echo $(( RANDOM % 60 ))
}

# Safely retrieve the current crontab entries
# Returns empty string if no crontab exists (handles "no crontab for user" error)
get_current_crontab() {
    # crontab -l returns exit code 1 if no crontab exists for the user
    # We capture stderr to suppress the "no crontab" message
    crontab -l 2>/dev/null || echo ""
}

# Remove any existing MDATP scan entry from the provided crontab content
# This filters out lines containing our unique marker
remove_existing_mdatp_entry() {
    local crontab_content="$1"
    
    # Use grep to exclude lines containing the marker
    # grep -v returns exit code 1 if no lines match, so we use || true
    echo "$crontab_content" | grep -v "$CRON_MARKER" || true
}

# Build the cron entry for the MDATP scan
# Format: minute hour * * day_of_week command # marker
# Sunday = 0 in cron
build_cron_entry() {
    local minute="$1"
    local hour="$2"
    
    # Cron format: minute hour day_of_month month day_of_week command
    # * * 0 means: any day of month, any month, on Sunday (0 = Sunday)
    echo "${minute} ${hour} * * 0 ${MDATP_CMD} scan ${SCAN_TYPE} ${CRON_MARKER}"
}

# Install the updated crontab using pipe (no temp file needed)
install_crontab() {
    local new_crontab_content="$1"
    
    # Pipe directly to crontab - more secure than temp files
    echo "$new_crontab_content" | crontab -
    
    log_info "Crontab updated successfully"
}

#-------------------------------------------------------------------------------
# Main Script Logic
#-------------------------------------------------------------------------------

main() {
    log_info "Starting MDATP weekly scan scheduler..."
    
    # Step 1: Verify running as root
    check_root
    
    # Step 2: Verify mdatp is installed
    check_mdatp_installed
    
    # Step 3: Generate random time for the scan
    local random_hour
    local random_minute
    random_hour=$(generate_random_hour)
    random_minute=$(generate_random_minute)
    
    log_info "Generated random scan time: Sunday at $(printf '%02d:%02d' "$random_hour" "$random_minute")"
    
    # Step 4: Get current crontab entries (safely handles case where none exist)
    local current_crontab
    current_crontab=$(get_current_crontab)
    
    # Step 5: Remove any existing MDATP scan entry to prevent duplicates
    local filtered_crontab
    filtered_crontab=$(remove_existing_mdatp_entry "$current_crontab")
    
    # Step 6: Build the new MDATP cron entry with the random time
    local new_cron_entry
    new_cron_entry=$(build_cron_entry "$random_minute" "$random_hour")
    
    log_info "New cron entry: $new_cron_entry"
    
    # Step 7: Combine existing entries with the new entry
    local new_crontab
    if [[ -n "$filtered_crontab" ]]; then
        new_crontab="${filtered_crontab}
${new_cron_entry}"
    else
        new_crontab="$new_cron_entry"
    fi
    
    # Step 8: Install the updated crontab
    install_crontab "$new_crontab"
    
    # Step 9: Display confirmation
    log_info "MDATP weekly scan scheduled successfully!"
    log_info "The scan will run every Sunday at $(printf '%02d:%02d' "$random_hour" "$random_minute")"
    log_info ""
    log_info "Current crontab entries:"
    crontab -l
}

# Run the main function
main "$@"