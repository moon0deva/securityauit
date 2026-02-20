# Advanced Linux Security Audit Tool - Ultimate v6.0

A professional-grade Linux security auditing tool that performs comprehensive system security analysis with beautiful HTML and PDF reports. **No external dependencies required** - works on any Linux distribution.

### Key Features

- 🔒 **Comprehensive Security Analysis** - Audits 8+ security categories
- 📊 **Professional Reports** - Generates Text, HTML, and PDF reports
- 🎨 **Beautiful Output** - Gradient styling and color-coded severity levels
- ⚡ **Zero Dependencies** - Pure Bash + Python, works everywhere
- 🚀 **Production Ready** - Tested and verified for enterprise use
- 📈 **Risk Assessment** - Identifies and prioritizes security issues
- 🔧 **Actionable Fixes** - Provides exact commands to fix issues

---

## Installation

```bash
git clone https://github.com/moon0deva/securityauit.git
cd securityauit
chmod +x securityaudit.sh
sudo ./securityaudit.sh
```

### System Requirements

- **OS:** Linux (Ubuntu, Debian, CentOS, RHEL, etc.)
- **Shell:** Bash 4.0+
- **Privileges:** Root access (via sudo) for full audit
- **Dependencies:** NONE (pure Bash + Python)

---
### Menu Options

```
1. Run FULL COMPREHENSIVE AUDIT          - All security checks (15-30 min)
2. Quick System Check                    - Basic security overview (2-3 min)
3. Network Security Only                 - Network and firewall checks (2-5 min)
4. User Security Only                    - User and account checks (1-2 min)
5. File System Security Only             - Permissions and SUID checks (2-5 min)
6. View Last Report                      - Display previous audit results
7. Exit                                  - Close the application
```

## Reports

### Report Location

All reports are saved to:
```
~/.security_audits/
```

### Report Files Generated

For each audit, three files are created with timestamp:

1. **security_audit_YYYYMMDD_HHMMSS.txt**
   - Full human-readable text report
   - All audit details and findings
   - Technical information

2. **security_audit_YYYYMMDD_HHMMSS.html**
   - Professional styled HTML report
   - Gradient backgrounds
   - Color-coded severity cards
   - Print-friendly formatting

3. **security_audit_YYYYMMDD_HHMMSS.pdf**
   - PDF version of the report
   - Generated from HTML
   - Perfect for sharing/emailing
   - Print-ready

### Viewing Reports

```bash
# View text report
cat ~/.security_audits/security_audit_*.txt

# View HTML report (on desktop)
open ~/.security_audits/security_audit_*.html

# View PDF report (on desktop)
open ~/.security_audits/security_audit_*.pdf

# Less command (works on servers)
less ~/.security_audits/security_audit_*.txt
```

---

## What Gets Audited

### System Information
- CPU, Memory, Disk metrics
- Security features (AppArmor, SELinux)
- Uptime and performance

### User Accounts
- User account enumeration
- Empty password detection
- Home directory verification
- Shell configuration analysis
- Sudo access review

### Network Security
- Listening ports analysis
- IPv6 capability check
- Connection statistics
- Active connections
- DNS configuration

### File System Security
- Critical file permissions
  - /etc/passwd
  - /etc/shadow
  - /etc/sudoers
  - /root/.ssh
- World-writable file detection
- SUID binary analysis
- Dangerous script interpreter check

### Security Services
- Firewall status (UFW)
- SSH configuration audit
- Fail2ban status
- Service verification

### Process Analysis
- Top resource-consuming processes
- Service enumeration
- Suspicious process detection

### Logging
- Failed login attempt tracking
- Brute force attack detection
- Auditd status

### Package Management
- Available updates tracking
- System package status
- Recent package review

---

## Issues Detected

### Critical Issues (Fix Immediately)
- ✗ Users with no password
- ✗ Dangerous SUID script interpreters
- ✗ World-readable sensitive files
- ✗ Disabled security features

### High Issues (Fix within 24 hours)
- ✗ Firewall disabled
- ✗ SSH root login enabled
- ✗ Insecure file permissions
- ✗ Failed login attacks
- ✗ NOPASSWD sudo entries

### Medium Issues (Fix within 1 week)
- ✗ Available system updates
- ✗ Recently modified binaries
- ✗ Unusual listening ports
- ✗ Missing home directories

### Low Issues (Monitor and fix)
- ✗ Auditd not installed
- ✗ Fail2ban not installed
- ✗ SSH password auth enabled

### Info (Informational)
- ✓ System metrics
- ✓ Enabled security features
- ✓ Proper account configuration

---
**Daily audit:**

```bash
# Add this line (runs daily at 6 AM)
0 6 * * * /path/to/security_audit_ultimate.sh
```

### Automating Report Analysis

```bash
# View today's audit
cat ~/.security_audits/security_audit_*.txt | grep -i critical

# Count issues by severity
cat ~/.security_audits/security_audit_*.txt | grep -c "CRITICAL"
```

### Integrating with Email

```bash
#!/bin/bash
# Email latest audit report

LATEST=$(ls -t ~/.security_audits/security_audit_*.pdf | head -1)
mail -s "Security Audit Report" admin@example.com < "$LATEST"
```

---
### Security Monitoring Tools

For enhanced security monitoring, install:

```bash
# Fail2ban - Brute force protection
sudo apt-get install -y fail2ban

# Auditd - System auditing
sudo apt-get install -y auditd

# chkrootkit - Rootkit detection
sudo apt-get install -y chkrootkit
```
### Recommended Frequency

- **Production Servers:** Weekly
- **Web Servers:** Weekly
- **Database Servers:** Weekly
- **Development Machines:** Monthly
- **Personal Workstations:** As needed

---
## FAQ

### Q: Does this script modify my system?
A: No, it's completely read-only. The script only reads system information and generates reports.

### Q: Can I run this without sudo?
A: Yes, but many checks will be limited. Run with `sudo` for comprehensive audit.

### Q: How often should I run this?
A: For production systems, weekly. For development, monthly or as needed.

### Q: Can I schedule this automatically?
A: Yes, use cron. Example: `0 2 * * 0 /path/to/script` (weekly Sunday 2 AM).

### Q: What if I don't have Python installed?
A: The script still works - HTML and text reports are always generated.

### Q: Can I export reports in other formats?
A: Currently supports TXT, HTML, and PDF. You can convert HTML to other formats manually.

### Q: Is this safe for production?
A: Yes, the script is read-only and makes no changes to your system.

### Q: What systems does it work on?
A: Any Linux distribution (Ubuntu, Debian, CentOS, RHEL, etc.).

---

## Version History

### v6.0 ULTIMATE (Current)
- ✅ Zero external dependencies
- ✅ Pure Bash + Python
- ✅ Works on any Linux system
- ✅ Automatic PDF generation
- ✅ Beautiful HTML reports

### v5.0 PRO
- 8 comprehensive audit categories
- 4 report formats
- CVE reference tracking

### v4.0
- HTML to PDF conversion
- Professional styling
- Issue detection

### v3.0
- PDF export
- Beautiful HTML reports
- Issue categorization

---
## Additional Resources

### System Security Hardening
- CIS Benchmarks: https://www.cisecurity.org/
- NIST Guidelines: https://www.nist.gov/
- Ubuntu Security Guide: https://ubuntu.com/security/

### Tools Recommended
- fail2ban - Brute force protection
- rkhunter - Rootkit detection
- aide - File integrity monitoring
- auditd - System auditing

---
