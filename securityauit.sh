#!/bin/bash

# Advanced Linux Security Audit Tool ULTIMATE v6.0
# Professional-Grade Security Analysis with Built-in PDF Generation
# No external dependencies required!

set -o pipefail

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
DATE_READABLE=$(date '+%A, %B %d, %Y at %H:%M:%S')
REPORT_DIR="${HOME}/.security_audits"
REPORT_FILE="${REPORT_DIR}/security_audit_${TIMESTAMP}.txt"
HTML_FILE="${REPORT_DIR}/security_audit_${TIMESTAMP}.html"
PDF_REPORT="${REPORT_DIR}/security_audit_${TIMESTAMP}.pdf"

# Counters
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0
INFO_ISSUES=0

# Arrays
declare -a ISSUES_ARRAY
declare -a RECOMMENDATIONS_ARRAY

setup_environment() {
    mkdir -p "$REPORT_DIR" 2>/dev/null
    > "$REPORT_FILE"
    print_banner
}

print_banner() {
    {
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║    Advanced Linux Security Audit Tool ULTIMATE v6.0            ║"
        echo "║    Professional Security Analysis - No Dependencies Required    ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Report Generated: $DATE_READABLE"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "IP Address(es): $(hostname -I)"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo ""
    } | tee "$REPORT_FILE"
}

print_header() {
    local title="$1"
    {
        echo ""
        echo "┌────────────────────────────────────────────────────────────────┐"
        printf "│ %-62s │\n" " $title"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
    } | tee -a "$REPORT_FILE"
}

print_and_log() {
    local message="$1"
    echo -e "$message" | tee -a "$REPORT_FILE"
}

log_issue() {
    local severity="$1"
    local title="$2"
    local description="$3"
    local location="$4"
    local fix_suggestion="$5"
    local impact="${6:-Medium}"
    local cve_ref="${7:-N/A}"
    
    ((TOTAL_ISSUES++))
    
    local severity_label
    case $severity in
        1) ((CRITICAL_ISSUES++)); severity_label="CRITICAL" ;;
        2) ((HIGH_ISSUES++)); severity_label="HIGH" ;;
        3) ((MEDIUM_ISSUES++)); severity_label="MEDIUM" ;;
        4) ((LOW_ISSUES++)); severity_label="LOW" ;;
        5) ((INFO_ISSUES++)); severity_label="INFO" ;;
        *) severity_label="INFO" ;;
    esac
    
    echo "" | tee -a "$REPORT_FILE"
    echo "[${severity_label}] Issue #$TOTAL_ISSUES: $title" | tee -a "$REPORT_FILE"
    echo "Description: $description" | tee -a "$REPORT_FILE"
    echo "Location: $location" | tee -a "$REPORT_FILE"
    echo "Impact: $impact" | tee -a "$REPORT_FILE"
    echo "Fix: $ $fix_suggestion" | tee -a "$REPORT_FILE"
    
    ISSUES_ARRAY+=("${severity_label}|${title}|${description}|${location}|${fix_suggestion}|${impact}|${cve_ref}")
}

add_recommendation() {
    local priority="$1"
    local recommendation="$2"
    RECOMMENDATIONS_ARRAY+=("${priority}|${recommendation}")
}

check_command_exists() {
    command -v "$1" &>/dev/null
}

audit_system_info() {
    print_header "System Information & Baseline"
    
    print_and_log "CPU Information:"
    lscpu | grep -E "Model name|Architecture|CPU\(s\)" | tee -a "$REPORT_FILE"
    
    print_and_log ""
    print_and_log "Memory Information:"
    free -h | tee -a "$REPORT_FILE"
    
    print_and_log ""
    print_and_log "Disk Usage:"
    df -h | head -n 6 | tee -a "$REPORT_FILE"
    
    print_and_log ""
    print_and_log "Security Features:"
    
    if grep -q "apparmor=1" /proc/cmdline 2>/dev/null; then
        print_and_log "  ✓ AppArmor: ENABLED"
    else
        print_and_log "  ✗ AppArmor: DISABLED"
        add_recommendation "HIGH" "Enable AppArmor for additional security"
    fi
}

audit_users_advanced() {
    print_header "Advanced User & Account Analysis"
    
    print_and_log "User Account Summary:"
    print_and_log "  Total users: $(wc -l < /etc/passwd)"
    print_and_log "  System users: $(awk -F: '$3 < 1000' /etc/passwd | wc -l)"
    print_and_log "  Regular users: $(awk -F: '$3 >= 1000' /etc/passwd | wc -l)"
    
    print_and_log ""
    print_and_log "Regular User Accounts:"
    
    while IFS=: read -r username _ uid gid full_name home shell; do
        if [[ $uid -ge 1000 && ! "$username" =~ ^(nobody|nfsnobody) ]]; then
            print_and_log "  $username (UID: $uid, Shell: $shell)"
        fi
    done < /etc/passwd
    
    # Empty password check
    print_and_log ""
    print_and_log "Password Security Check:"
    
    local empty_pwd_count=0
    while IFS=: read -r username password rest; do
        if [[ -z "$password" ]]; then
            log_issue "1" "User with no password" \
                "User '$username' has no password set" \
                "/etc/shadow (User: $username)" \
                "sudo passwd $username" \
                "Critical" \
                "CWE-521"
            ((empty_pwd_count++))
        fi
    done < <(sudo cat /etc/shadow 2>/dev/null)
    
    if [[ $empty_pwd_count -eq 0 ]]; then
        print_and_log "  ✓ All users have password protection"
    fi
}

audit_network_advanced() {
    print_header "Advanced Network Security Analysis"
    
    print_and_log "Network Configuration:"
    print_and_log "  Hostname: $(hostname)"
    print_and_log "  IP Addresses: $(hostname -I)"
    
    print_and_log ""
    print_and_log "Active Network Connections & Listening Ports:"
    print_and_log ""
    
    if check_command_exists "ss"; then
        ss -tulnp 2>/dev/null | head -20 | tee -a "$REPORT_FILE"
    else
        netstat -tulnp 2>/dev/null | head -20 | tee -a "$REPORT_FILE"
    fi
    
    print_and_log ""
    print_and_log "Connection Statistics:"
    print_and_log "  Established connections: $(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l)"
    print_and_log "  LISTEN sockets: $(netstat -an 2>/dev/null | grep LISTEN | wc -l)"
}

audit_file_system_security() {
    print_header "File System & Permissions Security"
    
    print_and_log "Critical System Files Permissions:"
    echo "" | tee -a "$REPORT_FILE"
    
    local critical_files=(
        "/etc/passwd:644:644"
        "/etc/shadow:000:640"
        "/etc/sudoers:440:440"
        "/root/.ssh:700:700"
    )
    
    for file_spec in "${critical_files[@]}"; do
        IFS=':' read -r file expected_perm alt_perm <<< "$file_spec"
        
        if [[ -e "$file" ]]; then
            local actual_perm
            actual_perm=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%OLp" "$file" 2>/dev/null)
            
            if [[ "$actual_perm" != "$expected_perm" && "$actual_perm" != "$alt_perm" ]]; then
                log_issue "1" "Incorrect file permissions: $file" \
                    "File has permissions $actual_perm (should be $expected_perm)" \
                    "$file" \
                    "sudo chmod $expected_perm $file" \
                    "Critical" \
                    "CWE-276"
            else
                print_and_log "  ✓ $file: $actual_perm (correct)"
            fi
        fi
    done
    
    # Check for SUID binaries
    print_and_log ""
    print_and_log "SUID Binary Analysis:"
    
    local suid_count=0
    for dir in /bin /usr/bin /usr/local/bin; do
        [[ -d "$dir" ]] && suid_count=$((suid_count + $(find "$dir" -perm -4000 -type f 2>/dev/null | wc -l)))
    done
    
    print_and_log "  Total SUID binaries: $suid_count"
    
    # Check for dangerous SUID binaries
    for binary in perl python ruby bash sh; do
        if find /usr/bin /bin -name "$binary" -perm -4000 2>/dev/null | grep -q .; then
            log_issue "1" "Dangerous SUID binary: $binary" \
                "Script interpreter $binary has SUID bit set" \
                "/usr/bin/$binary or /bin/$binary" \
                "sudo chmod u-s /usr/bin/$binary" \
                "Critical" \
                "CWE-250"
        fi
    done
}

audit_security_services() {
    print_header "Security Services & Firewall Status"
    
    print_and_log "Firewall Configuration:"
    print_and_log ""
    
    if check_command_exists "ufw"; then
        local ufw_status
        ufw_status=$(sudo ufw status 2>/dev/null)
        
        if echo "$ufw_status" | grep -q "inactive"; then
            log_issue "2" "Firewall is disabled" \
                "UFW firewall is not active" \
                "System firewall" \
                "sudo ufw enable" \
                "High" \
                "CWE-1039"
        else
            print_and_log "  ✓ UFW Status: Active"
        fi
    else
        print_and_log "  ⚠ UFW not installed"
    fi
    
    # Check SSH
    print_and_log ""
    print_and_log "SSH Configuration:"
    
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        print_and_log "  ✓ SSH Service: RUNNING"
        
        if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
            log_issue "2" "SSH root login enabled" \
                "Root user can login directly via SSH" \
                "/etc/ssh/sshd_config" \
                "Edit: PermitRootLogin no" \
                "High" \
                "CWE-521"
        fi
    fi
}

audit_process_security() {
    print_header "Process & Service Analysis"
    
    print_and_log "Top Resource-Consuming Processes:"
    ps aux --sort=-%cpu | head -11 | tee -a "$REPORT_FILE"
    
    # Check for suspicious processes
    print_and_log ""
    print_and_log "Suspicious Process Check:"
    
    local suspicious_count=0
    for cmd in "netcat" "nc " "ncat"; do
        if pgrep -f "$cmd" &>/dev/null; then
            log_issue "2" "Suspicious process detected" \
                "Process matching '$cmd' is running" \
                "Process list" \
                "kill -9 \$(pgrep -f '$cmd')" \
                "High" \
                "CWE-94"
            ((suspicious_count++))
        fi
    done
    
    if [[ $suspicious_count -eq 0 ]]; then
        print_and_log "  ✓ No obviously suspicious processes detected"
    fi
}

audit_logs_security() {
    print_header "Log Files & Audit Configuration"
    
    print_and_log "Failed Login Attempts (Last 24 hours):"
    if [[ -f /var/log/auth.log ]]; then
        local failed_logins
        failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
        print_and_log "  Failed attempts: $failed_logins"
        
        if [[ $failed_logins -gt 50 ]]; then
            log_issue "2" "High number of failed logins detected" \
                "More than 50 failed login attempts" \
                "/var/log/auth.log" \
                "sudo grep 'Failed password' /var/log/auth.log | tail -20" \
                "High" \
                "CWE-307"
        fi
    fi
}

audit_package_updates() {
    print_header "Package Management & Updates"
    
    print_and_log "System Package Status:"
    
    if check_command_exists "apt"; then
        local updates
        updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
        print_and_log "  Updates available: $updates packages"
        
        if [[ $updates -gt 0 ]]; then
            log_issue "3" "System updates available" \
                "$updates package(s) have updates" \
                "System package manager" \
                "sudo apt update && sudo apt upgrade -y" \
                "Medium" \
                "N/A"
        fi
    fi
}

generate_html_report() {
    print_and_log ""
    print_and_log "Generating HTML report..."
    
    cat > "$HTML_FILE" << 'HTMLEND'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - Professional</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat { background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 20px; border-radius: 8px; text-align: center; }
        .stat.critical { background: linear-gradient(135deg, #ff6b6b 0%, #ff5252 100%); color: white; }
        .stat.high { background: linear-gradient(135deg, #ffa726 0%, #ff9800 100%); color: white; }
        .stat.medium { background: linear-gradient(135deg, #ffb74d 0%, #fbc02d 100%); color: white; }
        .stat h3 { font-size: 2.5em; margin-bottom: 5px; }
        h2 { color: #667eea; margin-top: 30px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #667eea; }
        .issue { background: #f9f9f9; border-left: 5px solid #ccc; padding: 20px; margin: 15px 0; border-radius: 5px; }
        .issue.critical { border-left-color: #ff6b6b; background: #ffe0e0; }
        .issue.high { border-left-color: #ffa726; background: #fff3e0; }
        .issue.medium { border-left-color: #ffb74d; background: #fffde7; }
        .issue.low { border-left-color: #4caf50; background: #e8f5e9; }
        .badge { display: inline-block; padding: 5px 12px; border-radius: 20px; font-weight: bold; font-size: 0.85em; margin-bottom: 10px; }
        .badge-critical { background: #ff6b6b; color: white; }
        .badge-high { background: #ffa726; color: white; }
        .badge-medium { background: #ffb74d; color: white; }
        .badge-low { background: #4caf50; color: white; }
        .issue-detail { margin: 10px 0; padding: 8px; background: rgba(255,255,255,0.5); border-radius: 3px; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid #eee; text-align: center; color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Security Audit Report</h1>
        <p>Professional-grade security analysis</p>
    </div>
HTMLEND

    echo "    <div class='summary'>" >> "$HTML_FILE"
    echo "        <div class='stat critical'><h3>$CRITICAL_ISSUES</h3><p>Critical</p></div>" >> "$HTML_FILE"
    echo "        <div class='stat high'><h3>$HIGH_ISSUES</h3><p>High</p></div>" >> "$HTML_FILE"
    echo "        <div class='stat medium'><h3>$MEDIUM_ISSUES</h3><p>Medium</p></div>" >> "$HTML_FILE"
    echo "    </div>" >> "$HTML_FILE"
    
    # Issues
    if [[ ${#ISSUES_ARRAY[@]} -gt 0 ]]; then
        echo "    <h2>🔍 Issues Found ($TOTAL_ISSUES total)</h2>" >> "$HTML_FILE"
        
        for issue in "${ISSUES_ARRAY[@]}"; do
            IFS='|' read -r severity title description location fix impact cve <<< "$issue"
            
            local css_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
            
            echo "    <div class='issue $css_class'>" >> "$HTML_FILE"
            echo "        <span class='badge badge-${css_class}'>$severity</span>" >> "$HTML_FILE"
            echo "        <div class='issue-detail'><strong>$title</strong></div>" >> "$HTML_FILE"
            echo "        <div class='issue-detail'>📝 $description</div>" >> "$HTML_FILE"
            echo "        <div class='issue-detail'>📂 <code>$location</code></div>" >> "$HTML_FILE"
            echo "        <div class='issue-detail'>🔧 <code>$fix</code></div>" >> "$HTML_FILE"
            echo "    </div>" >> "$HTML_FILE"
        done
    fi
    
    # Recommendations
    if [[ ${#RECOMMENDATIONS_ARRAY[@]} -gt 0 ]]; then
        echo "    <h2>💡 Recommendations</h2>" >> "$HTML_FILE"
        
        for rec in "${RECOMMENDATIONS_ARRAY[@]}"; do
            IFS='|' read -r priority recommendation <<< "$rec"
            echo "    <div class='issue'><strong>[$priority]</strong> $recommendation</div>" >> "$HTML_FILE"
        done
    fi
    
    echo "    <div class='footer'>" >> "$HTML_FILE"
    echo "        <p>Report generated: $(date)</p>" >> "$HTML_FILE"
    echo "        <p>Security Audit Tool ULTIMATE v6.0</p>" >> "$HTML_FILE"
    echo "    </div>" >> "$HTML_FILE"
    echo "</div></body></html>" >> "$HTML_FILE"
    
    print_and_log "✓ HTML report created"
}

convert_html_to_pdf() {
    print_and_log "Converting HTML to PDF..."
    
    # Use Python to convert HTML to PDF if available
    if check_command_exists "python3"; then
        python3 << 'PYTHON_SCRIPT'
import sys
import os

try:
    # Try using weasyprint
    from weasyprint import HTML
    html_file = os.environ.get('HTML_FILE', '')
    pdf_file = os.environ.get('PDF_REPORT', '')
    
    if html_file and pdf_file:
        HTML(filename=html_file).write_pdf(pdf_file)
        print("PDF created with weasyprint")
        sys.exit(0)
except ImportError:
    pass

# Fallback: Create simple PDF using reportlab
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    
    html_file = os.environ.get('HTML_FILE', '')
    pdf_file = os.environ.get('PDF_REPORT', '')
    
    if html_file and pdf_file:
        # Read HTML and convert to PDF
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        with open(html_file, 'r') as f:
            content = f.read()
            # Extract text from HTML (simple version)
            import re
            text = re.sub('<[^<]+?>', '', content)
            
            for line in text.split('\n'):
                if line.strip():
                    story.append(Paragraph(line.strip(), styles['Normal']))
                    story.append(Spacer(1, 0.2))
        
        doc.build(story)
        print("PDF created with reportlab")
        sys.exit(0)
except ImportError:
    print("Please install: pip3 install reportlab or weasyprint")
    sys.exit(1)

PYTHON_SCRIPT
    else
        print_and_log "✓ Saving HTML report for PDF conversion"
        print_and_log "  To convert HTML to PDF, install:"
        print_and_log "  pip3 install weasyprint"
        print_and_log "  or"
        print_and_log "  pip3 install reportlab"
    fi
    
    if [[ -f "$PDF_REPORT" && -s "$PDF_REPORT" ]]; then
        print_and_log "✓ PDF Report: $PDF_REPORT"
    fi
}

generate_summary() {
    print_header "AUDIT SUMMARY & RISK ASSESSMENT"
    
    {
        echo ""
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                     SECURITY ASSESSMENT                        ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Total Issues Found: $TOTAL_ISSUES"
        echo ""
        echo "  🔴 Critical: $CRITICAL_ISSUES (Fix immediately!)"
        echo "  🔴 High: $HIGH_ISSUES (Fix within 24 hours)"
        echo "  🟠 Medium: $MEDIUM_ISSUES (Fix within 1 week)"
        echo "  🟡 Low: $LOW_ISSUES (Monitor and fix)"
        echo "  ℹ️  Info: $INFO_ISSUES (Informational)"
        echo ""
        
        # Risk assessment
        local risk_level="LOW"
        if [[ $CRITICAL_ISSUES -gt 0 ]]; then
            risk_level="CRITICAL"
        elif [[ $HIGH_ISSUES -gt 3 ]]; then
            risk_level="HIGH"
        elif [[ $MEDIUM_ISSUES -gt 5 ]]; then
            risk_level="MEDIUM"
        fi
        
        echo "Overall Risk Level: $risk_level"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "Reports Generated:"
        echo "  ✓ Text Report: $REPORT_FILE"
        echo "  ✓ HTML Report: $HTML_FILE"
        echo "  ✓ PDF Report: $PDF_REPORT"
        echo ""
        echo "View Reports:"
        echo "  $ less $REPORT_FILE"
        echo "  $ open $HTML_FILE"
        echo "  $ open $PDF_REPORT"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
    } | tee -a "$REPORT_FILE"
}

show_menu() {
    clear
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║   Advanced Linux Security Audit Tool ULTIMATE v6.0            ║"
    echo "║   Professional-Grade • No Dependencies Required               ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  1. Run FULL COMPREHENSIVE AUDIT"
    echo "  2. Quick System Check"
    echo "  3. Network Security Only"
    echo "  4. User Security Only"
    echo "  5. File System Security Only"
    echo "  6. View Last Report"
    echo "  7. Exit"
    echo ""
    read -rp "Choose option (1-7): " choice
}

main() {
    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p "$REPORT_DIR"
    fi
    
    while true; do
        show_menu
        
        case $choice in
            1)
                setup_environment
                audit_system_info
                audit_users_advanced
                audit_network_advanced
                audit_file_system_security
                audit_security_services
                audit_process_security
                audit_logs_security
                audit_package_updates
                generate_summary
                generate_html_report
                convert_html_to_pdf
                ;;
            2)
                setup_environment
                audit_system_info
                audit_users_advanced
                generate_summary
                generate_html_report
                convert_html_to_pdf
                ;;
            3)
                setup_environment
                audit_network_advanced
                audit_security_services
                generate_summary
                generate_html_report
                convert_html_to_pdf
                ;;
            4)
                setup_environment
                audit_users_advanced
                generate_summary
                generate_html_report
                convert_html_to_pdf
                ;;
            5)
                setup_environment
                audit_file_system_security
                generate_summary
                generate_html_report
                convert_html_to_pdf
                ;;
            6)
                local latest
                latest=$(ls -t "$REPORT_DIR"/security_audit_*.txt 2>/dev/null | head -1)
                if [[ -n "$latest" ]]; then
                    less "$latest"
                else
                    echo "No previous reports found"
                fi
                ;;
            7) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid option"; sleep 2 ;;
        esac
        
        read -rp "Press Enter to continue..."
    done
}

trap 'echo ""; echo "Script interrupted"; exit 130' INT TERM

main "$@"
