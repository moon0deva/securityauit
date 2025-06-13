#!/bin/bash

REPORT=~/security_audit_report.txt
> "$REPORT"

function print_and_log() {
    echo -e "$1"
    echo -e "$1" >> "$REPORT"
}

function check_dependencies() {
    DEPS=(chkrootkit rkhunter aide net-tools lsof)
    for pkg in "${DEPS[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            print_and_log "[*] Installing missing package: $pkg"
            sudo apt-get update && sudo apt-get install -y "$pkg"
        fi
    done
}

function suspicious_users() {
    print_and_log "\n--- Suspicious Users (UID >= 1000) ---"
    awk -F: '$3 >= 1000 {print $1}' /etc/passwd >> "$REPORT"
}

function active_connections() {
    print_and_log "\n--- Active Network Connections ---"
    netstat -tulnp >> "$REPORT" 2>/dev/null || ss -tulnp >> "$REPORT"
}

function unknown_processes() {
    print_and_log "\n--- Unknown or Suspicious Processes ---"
    ps aux | grep -vE 'root|your_expected_user|grep' >> "$REPORT"
}

function cron_jobs() {
    print_and_log "\n--- Cron Jobs ---"
    ls -la /etc/cron* /var/spool/cron 2>/dev/null >> "$REPORT"
}

function modified_binaries() {
    print_and_log "\n--- Recently Modified System Binaries (last 5 days) ---"
    find /bin /usr/bin -type f -mtime -5 2>/dev/null >> "$REPORT"
}

function rootkit_scan() {
    print_and_log "\n--- chkrootkit Scan ---"
    sudo chkrootkit >> "$REPORT"

    print_and_log "\n--- rkhunter Scan ---"
    sudo rkhunter --update
    sudo rkhunter --checkall --sk >> "$REPORT"
}

function file_integrity_check() {
    print_and_log "\n--- File Integrity (AIDE) ---"
    sudo aideinit
    sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    sudo aide --check >> "$REPORT"
}

function autostart_check() {
    print_and_log "\n--- Suspicious Autostart Entries ---"
    ls -la ~/.config/autostart /etc/init.d /etc/systemd/system 2>/dev/null >> "$REPORT"
}

function suid_check() {
    print_and_log "\n--- SUID Binaries ---"
    find / -perm -4000 -type f 2>/dev/null >> "$REPORT"
}

function shell_history() {
    print_and_log "\n--- Shell History (Last 50 Commands) ---"
    tail -n 50 ~/.bash_history >> "$REPORT"
}

function login_activity() {
    print_and_log "\n--- Current Logged-in Users ---"
    who >> "$REPORT"
    print_and_log "\n--- User Activity ---"
    w >> "$REPORT"
}

function hidden_connections() {
    print_and_log "\n--- Hidden/External Network Connections ---"
    lsof -i -nP | grep -v "127.0.0.1" >> "$REPORT"
}

function main_menu() {
    clear
    echo "========== Linux Security Audit Script =========="
    echo "1. Run Full System Audit"
    echo "2. Check Only Suspicious Users"
    echo "3. Check Network Connections"
    echo "4. Check Cron Jobs and Autostarts"
    echo "5. Scan for Rootkits"
    echo "6. Perform File Integrity Check"
    echo "7. Exit"
    echo "=============================================="
    read -rp "Choose an option: " choice

    case $choice in
        1)
            check_dependencies
            suspicious_users
            active_connections
            unknown_processes
            cron_jobs
            modified_binaries
            autostart_check
            rootkit_scan
            file_integrity_check
            suid_check
            shell_history
            login_activity
            hidden_connections
            ;;
        2) suspicious_users ;;
        3) active_connections ;;
        4) cron_jobs && autostart_check ;;
        5) rootkit_scan ;;
        6) file_integrity_check ;;
        7) echo "Goodbye! Report saved at $REPORT"; exit 0 ;;
        *) echo "Invalid choice. Try again."; sleep 1; main_menu ;;
    esac

    echo -e "\n✅ Audit Complete. Report saved to: $REPORT"
}

main_menu
