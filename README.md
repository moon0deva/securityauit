This is a simple but powerful Bash script that helps you check the security health of your Linux machine. Whether you're a system admin, an ethical hacker, or just someone who wants to tighten up your system — this tool's for you.

It runs a bunch of security checks and gives you a nice little report you can review later. No fancy tools or paid apps. Just raw Linux goodness.

**What It Does**

- **Suspicious Users**– Lists non-system users (UIDs 1000+)
- **Network Activity** – Shows what’s connected to your system
- **Weird Processes** – Flags anything unexpected that's running
- **Cron Jobs & Autostarts** – Lists scheduled and auto-started tasks
- **Rootkit Scan**– Uses `chkrootkit` and `rkhunter`
- **File Integrity Check** – Scans for unauthorized file changes with AIDE
- **Recently Modified Binaries** – Finds recently changed important files
- **SUID Binaries** – Flags binaries with potential privilege escalation risks
- **Shell History** – Shows the last 50 commands you typed
- **User Logins** – Who’s logged in and what they’re doing
- **Hidden Network Connections** – Spots any sketchy external activity

<pre><code> 
git clone https://github.com/moon0deva/securityauit.git
cd securityauit
chmod +x securityauit.sh
bash securityauit.sh
</code></pre>

