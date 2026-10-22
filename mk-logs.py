#!/usr/bin/env python3
# ================================================================
#
#   MK-ULTRA · MK-logs  v2
#   Linux log analyzer — detections, correlation, MITRE ATT&CK,
#   and a disk-space cleanup assistant.
#
# ================================================================
# Usage:
#   sudo python3 mk-logs.py                      # interactive menu
#   sudo python3 mk-logs.py --quick              # scan everything, no menu
#   python3 mk-logs.py --file auth.log           # analyze a specific file (all time)
#   python3 mk-logs.py --hours 72 --rotated      # last 72h, include rotated logs
#   python3 mk-logs.py --format json -o out.json # machine-readable report
#   sudo python3 mk-logs.py --cleanup            # disk / log cleanup assistant
#   python3 mk-logs.py --root /mnt/evidence      # analyze a mounted disk image
#   python3 mk-logs.py --list-rules              # show every detection rule
#   python3 mk-logs.py --dump-rules > rules.yaml # export rules to edit
#
# Exit codes: 0 = nothing notable, 1 = medium findings, 2 = high/critical
# ================================================================

import argparse
import bisect
import bz2
import csv
import glob
import gzip
import io
import ipaddress
import json
import lzma
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

VERSION = "2.0.0"

# ── colours ──────────────────────────────────────────────────
ANSI = {
    "red": "\033[0;31m", "yellow": "\033[1;33m", "green": "\033[0;32m",
    "cyan": "\033[0;36m", "white": "\033[1;37m", "dim": "\033[2m",
    "bold": "\033[1m", "magenta": "\033[1;35m",
}
RESET = "\033[0m"
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text, *styles):
    if not USE_COLOR or not styles:
        return str(text)
    return "".join(ANSI[s] for s in styles) + str(text) + RESET


SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_STYLE = {
    "info": ("dim",), "low": ("cyan",), "medium": ("yellow",),
    "high": ("red",), "critical": ("bold", "magenta"),
}


def sev_tag(sev):
    return c(f"[{sev.upper()}]", *SEV_STYLE[sev])


BANNER = r"""
{dim}════════════════════════════════════════════════════════{rst}
{bld}{wht}
         ███╗   ███╗██╗  ██╗      ██╗      ██████╗  ██████╗ ███████╗
         ████╗ ████║██║ ██╔╝      ██║     ██╔═══██╗██╔════╝ ██╔════╝
         ██╔████╔██║█████╔╝ █████╗██║     ██║   ██║██║  ███╗███████╗
         ██║╚██╔╝██║██╔═██╗ ╚════╝██║     ██║   ██║██║   ██║╚════██║
         ██║ ╚═╝ ██║██║  ██╗      ███████╗╚██████╔╝╚██████╔╝███████║
         ╚═╝     ╚═╝╚═╝  ╚═╝      ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝
{rst}{dim}
              Linux Log Analyzer · v{ver}
              Detections · Correlation · MITRE ATT&CK · Cleanup
{rst}{dim}════════════════════════════════════════════════════════{rst}"""


def banner():
    return BANNER.format(
        dim=ANSI["dim"] if USE_COLOR else "", rst=RESET if USE_COLOR else "",
        bld=ANSI["bold"] if USE_COLOR else "", wht=ANSI["white"] if USE_COLOR else "",
        ver=VERSION)


# ── MITRE ATT&CK technique names (shown next to IDs) ─────────
MITRE_NAMES = {
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1014": "Rootkit",
    "T1021.004": "Remote Services: SSH",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1078": "Valid Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1098": "Account Manipulation",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1190": "Exploit Public-Facing Application",
    "T1222.002": "File and Directory Permissions Modification: Linux and Mac",
    "T1496": "Resource Hijacking",
    "T1505.003": "Server Software Component: Web Shell",
    "T1548.001": "Abuse Elevation Control: Setuid and Setgid",
    "T1548.003": "Abuse Elevation Control: Sudo and Sudo Caching",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
    "T1574.006": "Hijack Execution Flow: Dynamic Linker Hijacking",
    "T1595": "Active Scanning",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
}


def mitre_label(tid):
    return f"{tid} {MITRE_NAMES[tid]}" if tid in MITRE_NAMES else tid


# ══════════════════════════════════════════════════════════════
#  DEFAULT RULES
#  Every rule is a plain dict, so the same structure can live in
#  a YAML/JSON file.  Run  --dump-rules  to export them.
#
#  Fields:  id, name, severity (info|low|medium|high|critical),
#           category, sources, pattern (regex), exclude (regex, optional),
#           event (feeds the correlation engine), mitre (list),
#           ignorecase (default true), enabled (default true), description
#
#  Philosophy: normal service behaviour (sudo use, cron jobs, firewall
#  blocks, SSH disconnects, apt activity) is NOT flagged on its own.
#  Rules look for attacker *behaviour*, or only matter in volume — and
#  volume is handled by the correlation engine, not by regex.
# ══════════════════════════════════════════════════════════════
IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
SSHD = r"sshd(?:-session)?\[\d+\]: "
SUDO = r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : "
WEB = r"^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] \""   # access-log prefix, ends at opening quote
EXEC_SRC = ["auth", "shell", "audit", "syslog", "cron"]
SENSITIVE_LOGS = r"/var/log/(?:auth\.log|secure|wtmp|btmp|lastlog|audit/|syslog|messages)"


def rule(rid, name, severity, category, sources, pattern, desc,
         mitre=None, event=None, exclude=None, ignorecase=None):
    r = {"id": rid, "name": name, "severity": severity, "category": category,
         "sources": sources}
    if event:
        r["event"] = event
    r["mitre"] = mitre or []
    r["pattern"] = pattern
    if exclude:
        r["exclude"] = exclude
    if ignorecase is not None:
        r["ignorecase"] = ignorecase
    r["description"] = desc
    return r


DEFAULT_RULES = [
    # ── authentication ───────────────────────────────────────
    rule("ssh-failed-login", "SSH failed login", "low", "authentication", ["auth"],
         SSHD + r"Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
         r"(?:invalid user )?(?P<user>\S+) from " + IP + r" port",
         "One failed SSH login. Harmless alone; matters in volume (see brute-force detection).",
         mitre=["T1110.001"], event="auth_fail"),
    rule("ssh-invalid-user", "SSH login attempt for non-existent user", "low", "authentication", ["auth"],
         SSHD + r"Invalid user (?P<user>\S*) from " + IP,
         "Someone is guessing usernames that don't exist on this box.",
         mitre=["T1110.001"]),
    rule("ssh-max-auth-tries", "SSH max authentication attempts exceeded", "low", "authentication", ["auth"],
         r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from " + IP + r" port",
         "A client burned through all its allowed password tries in one connection.",
         mitre=["T1110.001"]),
    rule("ssh-scanner-probe", "SSH scanner / protocol probe", "low", "recon", ["auth"],
         SSHD + r"(?:Did not receive identification string from|Unable to negotiate with|"
         r"Bad protocol version identification .{0,200}? from) " + IP,
         "Internet scanners poking at port 22. Normal background noise on public hosts.",
         mitre=["T1595"]),
    rule("ssh-accepted", "SSH login accepted", "info", "authentication", ["auth"],
         SSHD + r"Accepted (?P<method>[\w-]+) for (?P<user>\S+) from " + IP + r" port",
         "Successful SSH login. Info only; feeds success-after-failure correlation.",
         mitre=["T1078"], event="auth_success"),
    rule("ssh-root-login", "Direct root login over SSH", "medium", "authentication", ["auth"],
         SSHD + r"Accepted \S+ for root from " + IP + r" port",
         "Root logged in directly. Best practice is PermitRootLogin no + sudo from a normal user.",
         mitre=["T1078.003"]),
    rule("sudo-bad-password", "Sudo password failure", "low", "authentication", ["auth", "syslog"],
         r"sudo(?:\[\d+\])?:\s+(?:(?P<user>\S+) : \d+ incorrect password attempts?|"
         r"pam_unix\(sudo:auth\): authentication failure)",
         "A user mistyped their sudo password. One is a typo, many is guessing.",
         mitre=["T1110.001"]),
    rule("sudo-not-in-sudoers", "Sudo attempted without permission", "medium", "privilege-escalation",
         ["auth", "syslog"],
         r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : (?:user NOT in sudoers|command not allowed)",
         "A user tried to use sudo and isn't allowed to. Check who and why.",
         mitre=["T1548.003"]),
    rule("su-failed", "su authentication failure", "low", "authentication", ["auth", "syslog"],
         r"\bsu(?:\[\d+\])?: (?:pam_unix\(su(?:-l)?:auth\): authentication failure|FAILED SU)",
         "Failed attempt to switch user.", mitre=["T1110.001"]),
    rule("sudo-root-shell", "Sudo used to open a root shell", "low", "privilege-escalation", ["auth", "syslog"],
         SUDO + r".*COMMAND=(?:/usr)?/s?bin/(?:su|bash|sh|zsh|dash|fish)(?:\s|$)",
         "Someone ran sudo -i / sudo su / sudo bash. Routine for admins, notable for everyone else.",
         mitre=["T1548.003"]),
    rule("sudo-credential-files", "Sudo touching shadow/sudoers files", "medium", "privilege-escalation",
         ["auth", "syslog"],
         SUDO + r".*COMMAND=.*(?:/etc/shadow|/etc/gshadow|/etc/sudoers)",
         "Privileged access to password hashes or sudo policy.",
         mitre=["T1003.008", "T1548.003"]),

    # ── accounts / persistence ───────────────────────────────
    rule("user-created", "New login-capable user account", "medium", "persistence", ["auth", "syslog"],
         r"useradd\[\d+\]: new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=\d+, "
         r"home=(?P<home>[^,]*), shell=(?P<shell>\S+)",
         "A real user account was created. System accounts (UID < 1000 / nologin shells, "
         "e.g. created by package installs) are ignored.",
         mitre=["T1136.001"], exclude=r"UID=[1-9]\d{0,2},|shell=\S*(?:nologin|/false)\b"),
    rule("user-uid0", "Account created with UID 0 (root-equivalent)", "critical", "persistence",
         ["auth", "syslog"],
         r"useradd\[\d+\]: new user: name=(?P<user>[^,]+), UID=0,",
         "A second root-equivalent account is a classic backdoor.", mitre=["T1136.001"]),
    rule("priv-group-add", "User added to a privileged group", "high", "persistence", ["auth", "syslog"],
         r"usermod\[\d+\]: add '(?P<user>[^']+)' to (?:shadow )?group '"
         r"(?P<group>sudo|wheel|admin|root|adm|docker|lxd)'|"
         r"adduser\[\d+\]: Adding user .(?P<user2>\S+). to group .(?P<group2>sudo|wheel|admin|docker|lxd).",
         "sudo/wheel/admin give root; docker/lxd are root-equivalent.", mitre=["T1098"]),
    rule("password-changed", "Account password changed", "low", "persistence", ["auth", "syslog"],
         r"(?:passwd|chpasswd)\[\d+\]: pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<user>\S+)",
         "A password was changed. Expected for users; suspicious if you didn't do it.",
         mitre=["T1098"]),
    rule("passwd-shadow-write", "Direct write to /etc/passwd or /etc/shadow", "high", "persistence",
         ["shell", "auth"],
         r"(?:>>?\s*|\btee\b(?:\s+-a)?\s+)/etc/(?:passwd|shadow)\b",
         "Editing account files by hand is how backdoor accounts get created.",
         mitre=["T1098", "T1136.001"]),
    rule("sudoers-write", "Write to sudoers", "medium", "persistence", ["shell", "auth"],
         r"(?:>>?\s*|\btee\b(?:\s+-a)?\s+)/etc/sudoers(?:\.d/\S+)?\b",
         "Sudo policy modified from the command line.", mitre=["T1548.003"]),
    rule("authorized-keys-write", "SSH authorized_keys modified", "medium", "persistence", ["shell", "auth"],
         r">>?\s*\S*authorized_keys\b|\btee\b(?:\s+-a)?\s+\S*authorized_keys\b",
         "A new SSH key was appended. Verify it is yours.", mitre=["T1098.004"]),
    rule("cron-suspicious-cmd", "Cron job running suspicious command", "medium", "persistence",
         ["cron", "syslog"],
         r"CRON\[\d+\]: \((?P<user>\S+)\) CMD \(.{0,300}?(?:\bnc\b|\bncat\b|/dev/tcp/|\bbase64\b|"
         r"\bcurl\b[^)]{0,200}\|\s*(?:ba)?sh|\bwget\b[^)]{0,200}\|\s*(?:ba)?sh|/dev/shm/|/tmp/\S+\.sh)",
         "A scheduled job is fetching/piping code or running from a temp dir. Normal cron jobs "
         "are deliberately NOT flagged.",
         mitre=["T1053.003"]),
    rule("crontab-replaced", "Crontab replaced", "low", "persistence", ["cron", "syslog"],
         r"crontab\[\d+\]: \((?P<user>\S+)\) REPLACE \(",
         "A user's crontab was rewritten.", mitre=["T1053.003"]),

    # ── execution / defence evasion (commands) ───────────────
    rule("reverse-shell", "Reverse shell pattern", "critical", "execution", EXEC_SRC,
         r"\bbash\s+-i\s*>&?\s*/dev/(?:tcp|udp)/"
         r"|/dev/(?:tcp|udp)/\d{1,3}(?:\.\d{1,3}){3}/\d+"
         r"|\b(?:nc|ncat|netcat)\b\s+(?:\S+\s+){0,6}?(?:-e|-c|--exec|--sh-exec)\s+\S*(?:sh|bash)\b"
         r"|\bmkfifo\b.{0,80}\b(?:nc|ncat|netcat)\b"
         r"|\bsocat\b.{0,120}\bexec:.{0,40}(?:sh|bash)"
         r"|\bpython[\d.]*\s+-c\s+.{0,200}\bsocket\b.{0,200}\b(?:subprocess|pty\.spawn|os\.dup2)\b"
         r"|\bperl\s+-e\s+.{0,200}\bsocket\b.{0,200}\bexec\b"
         r"|\bphp\s+-r\s+.{0,200}\bfsockopen\b",
         "Command line matches a known reverse-shell one-liner. Treat as compromise until proven otherwise.",
         mitre=["T1059.004"]),
    rule("download-and-exec", "Remote script piped into a shell", "medium", "execution",
         ["auth", "shell", "cron", "audit"],
         r"\b(?:curl|wget)\b[^|;&]{0,300}\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b",
         "curl | sh runs unreviewed code. Common installers (docker, rustup, nodesource, nvm, "
         "poetry, oh-my-zsh, sdkman, brew) are excluded.",
         mitre=["T1105", "T1059.004"],
         exclude=r"get\.docker\.com|sh\.rustup\.rs|deb\.nodesource\.com|nvm-sh/nvm|"
                 r"install\.python-poetry\.org|ohmyz\.sh|get\.sdkman\.io|brew\.sh"),
    rule("base64-decode-exec", "Base64-decoded payload piped into a shell", "high", "execution",
         ["auth", "shell", "cron", "audit"],
         r"\bbase64\b[^|;&]{0,50}(?:-d|--decode)\b[^;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
         "Obfuscated command execution.", mitre=["T1140", "T1059.004"]),
    rule("exec-from-tmp", "Executable staged in /tmp, /dev/shm or /var/tmp", "medium", "execution",
         ["auth", "shell"],
         r"\bchmod\s+(?:[ugoa]*\+x|[0-7]?7[0-7]{2})\s+/(?:tmp|dev/shm|var/tmp)/|"
         r"COMMAND=/(?:tmp|dev/shm|var/tmp)/\S+",
         "World-writable directories are where attackers drop payloads.",
         mitre=["T1222.002", "T1059.004"]),
    rule("setuid-set", "Setuid/setgid bit set", "medium", "privilege-escalation", ["auth", "shell"],
         r"\bchmod\s+(?:[ugoa]*\+s\b|[2467][0-7]{3}\b)",
         "setuid binaries run as their owner. Setgid on shared directories (e.g. 2775) is normal.",
         mitre=["T1548.001"]),
    rule("crypto-miner", "Cryptominer indicator", "high", "impact", ["any"],
         r"\b(?:xmrig|minerd|cpuminer|ethminer|kdevtmpfsi|kinsing)\b|stratum\+(?:tcp|ssl)://|"
         r"\b(?:pool\.)?(?:minexmr|supportxmr|nanopool|2miners|hashvault)\.\w+",
         "Known miner names or mining-pool URLs.", mitre=["T1496"]),
    rule("ld-preload", "LD_PRELOAD / ld.so.preload usage", "high", "evasion", ["auth", "shell", "audit"],
         r"/etc/ld\.so\.preload|\bLD_PRELOAD=",
         "Userland rootkits hook libc this way.", mitre=["T1574.006"]),
    rule("security-control-disabled", "Firewall / logging / security service disabled", "medium", "evasion",
         ["auth", "shell"],
         r"(?:COMMAND=\S*/|^\s*(?:sudo\s+)?|[;&|]\s*(?:sudo\s+)?)"
         r"(?:ufw\s+(?:disable|--force\s+reset)|iptables\s+(?:-F|--flush)\b|nft\s+flush\s+ruleset|"
         r"systemctl\s+(?:stop|disable|mask)\s+(?:ufw|firewalld|fail2ban|auditd|apparmor|rsyslog)\b|"
         r"service\s+(?:ufw|firewalld|fail2ban|auditd|rsyslog)\s+stop|setenforce\s+0|auditctl\s+-e\s*0)",
         "Someone turned off a defence. Expected during maintenance, suspicious otherwise.",
         mitre=["T1562.001", "T1562.004"]),
    rule("log-tampering", "Authentication/system logs deleted or truncated", "high", "evasion",
         ["auth", "shell", "audit"],
         r"(?:\b(?:rm|shred|truncate|unlink)\b|>\s*|\bcat\s+/dev/null\s*>\s*)[^|;&]{0,120}?" + SENSITIVE_LOGS,
         "Wiping auth/wtmp/audit logs is anti-forensics. If this was you freeing disk space, "
         "use --cleanup instead (it archives first) or add the line to your allowlist.",
         mitre=["T1070.002"]),
    rule("log-deletion", "Log file deleted", "medium", "evasion", ["auth", "shell", "audit"],
         r"\b(?:rm|shred|truncate)\b[^|;&]{0,120}?/var/log/",
         "Something under /var/log was removed. Usually housekeeping — check who and what.",
         mitre=["T1070.002"], exclude=SENSITIVE_LOGS + r"|logrotate"),
    rule("history-tampering", "Shell history cleared or disabled", "high", "evasion", ["shell", "auth"],
         r"\bhistory\s+-c\b|\bunset\s+HISTFILE|\bHISTFILE=/dev/null|\bHISTSIZE=0\b|"
         r"\b(?:rm|shred|truncate)\b[^|;&]{0,80}\.(?:bash|zsh)_history|ln\s+-sf?\s+/dev/null\s+\S*history",
         "Covering tracks after interactive activity.", mitre=["T1070.003"]),
    rule("rootkit-scanner-warning", "rkhunter warning", "medium", "evasion", ["rkhunter"],
         r"^\[[\d: ]+\]\s+Warning:",
         "rkhunter flagged something. Many warnings are benign after package updates "
         "(fix with: rkhunter --propupd) — review before panicking.",
         mitre=["T1014"]),
    rule("chkrootkit-infected", "chkrootkit INFECTED result", "high", "evasion", ["chkrootkit"],
         r"\bINFECTED\b",
         "chkrootkit reports a match. It has known false positives (e.g. port 465/Xorg) — verify manually.",
         mitre=["T1014"], ignorecase=False),

    # ── firewall / bans (feed correlation) ───────────────────
    rule("ufw-block", "UFW blocked packet", "info", "recon", ["ufw", "kern", "syslog"],
         r"\[UFW BLOCK\].*?\bSRC=(?P<ip>[0-9A-Fa-f:.]+)\b.*?\bDPT=(?P<dport>\d+)",
         "Normal firewall behaviour. Only matters when one IP sweeps many ports (port-scan detection).",
         mitre=["T1595"], event="fw_block"),
    rule("fail2ban-ban", "Fail2Ban banned an IP", "info", "authentication", ["fail2ban"],
         r"\[(?P<jail>[^\]]+)\] Ban " + IP,
         "Fail2Ban did its job.", event="banned"),

    # ── web server access logs ───────────────────────────────
    rule("web-sqli", "SQL injection attempt", "high", "web", ["web"],
         WEB + r"[^\"]*?(?:\bunion(?:\s|%20|\+|/\*\*/)+(?:all(?:\s|%20|\+)+)?select\b|\binformation_schema\b|"
         r"\bsleep\((?:\d|%28)|\bbenchmark\(|(?:'|%27)(?:\s|%20|\+)*(?:or|and)(?:\s|%20|\+)+(?:'|%27)?\d+"
         r"(?:'|%27)?(?:\s|%20|\+)*(?:=|%3d)(?:\s|%20|\+)*(?:'|%27)?\d+|\bwaitfor(?:\s|%20|\+)+delay\b)",
         "Classic SQLi probes in the request line.", mitre=["T1190"]),
    rule("web-path-traversal", "Path traversal attempt", "medium", "web", ["web"],
         WEB + r"[^\"]*?(?:(?:\.\./|%2e%2e(?:%2f|/)|\.\.%2f|%252e%252e){2,}|\.\.\\)",
         "Repeated ../ sequences trying to escape the web root.", mitre=["T1190"]),
    rule("web-sensitive-file-read", "Request for OS secrets (/etc/passwd etc.)", "high", "web", ["web"],
         WEB + r"[^\"]*?(?:/etc/(?:passwd|shadow)|/proc/self/(?:environ|cmdline)|\bboot\.ini\b|"
         r"\bwin\.ini\b|/\.ssh/id_[a-z]+)",
         "Local-file-inclusion style probing.", mitre=["T1190"]),
    rule("web-rce-probe", "Remote code execution probe", "high", "web", ["web"],
         WEB + r"[^\"]*?(?:\$\{jndi:|%24%7bjndi|\(\)\s*\{\s*:;\s*\};|\(\)%20%7b|/bin/(?:ba)?sh\b|cmd\.exe|"
         r"powershell(?:\.exe)?%20|;(?:%20|\s|\+)*(?:wget|curl)(?:%20|\s|\+)|\bphp://input|\bdata://text|"
         r"allow_url_include)",
         "Log4Shell, Shellshock, command injection and PHP wrapper probes.", mitre=["T1190"]),
    rule("web-scanner-ua", "Known vulnerability scanner user-agent", "medium", "web", ["web"],
         WEB + r".*(?:sqlmap|nikto|masscan|gobuster|dirbuster|wpscan|nuclei|acunetix|nessus|openvas|"
         r"feroxbuster|\bffuf\b|zgrab|nmap scripting engine|\bhydra\b|havij|w3af)",
         "Automated scanner hitting your site.", mitre=["T1595.002"]),
    rule("web-shell-probe", "Web shell probe", "medium", "web", ["web"],
         WEB + r"[^\"]*?(?:/(?:c99|r57|wso|b374k|alfa|indoxploit|webshell|shell|cmd)\.php|"
         r"/(?:eval-stdin|phpunit)\.php|/vendor/phpunit/)",
         "Looking for dropped shells or vulnerable PHPUnit.", mitre=["T1505.003", "T1190"]),
    rule("web-sensitive-file-probe", "Probe for sensitive file", "low", "web", ["web"],
         WEB + r"(?:GET|POST|HEAD) /(?:\.env\b|\.git/|\.aws/|\.ssh/|\.svn/|\.DS_Store|\.htpasswd|wp-config\.php|"
         r"config\.php\.(?:bak|old|save)|phpmyadmin|phpinfo\.php|server-status|actuator/|"
         r"backup\.(?:sql|zip|tar\.gz))",
         "Daily background noise on any public server; not an incident unless it returned 200.",
         mitre=["T1595.002"]),
    rule("web-sensitive-file-exposed", "Sensitive file served successfully (HTTP 200)", "high", "web", ["web"],
         WEB + r"GET /(?:\.env|\.git/(?:config|HEAD)|\.aws/credentials|\.ssh/id_rsa|\.htpasswd|"
         r"backup\.(?:sql|zip|tar\.gz))\S* [^\"]*\" 200 ",
         "A secrets file was actually delivered. Fix the server config and rotate anything inside it.",
         mitre=["T1552.001", "T1190"]),
    rule("web-404", "Web 404 response", "info", "web", ["web"],
         WEB + r"[^\"]*\" 404 ",
         "Feeds web-scan detection (many 404s from one IP).", mitre=["T1595.002"], event="web_404"),
    rule("web-auth-failure", "Web login rejected (401/403)", "info", "web", ["web"],
         WEB + r"(?:POST|GET) [^\"]*(?:login|wp-login|xmlrpc|admin|signin|auth)[^\"]*\" (?:401|403) ",
         "Feeds web brute-force detection.", mitre=["T1110"], event="web_authfail"),

    # ── auditd ───────────────────────────────────────────────
    rule("audit-anomaly", "auditd anomaly event", "medium", "audit", ["audit"],
         r"type=ANOM_(?:PROMISCUOUS|LOGIN_FAILURES|LOGIN_LOCATION|LOGIN_SESSIONS|LOGIN_TIME|ACCESS_FS|EXEC|"
         r"ADD_ACCT|DEL_ACCT|MOD_ACCT)",
         "auditd raised an anomaly (e.g. interface in promiscuous mode, account changes)."),
    rule("audit-disabled", "auditd turned off", "high", "evasion", ["audit"],
         r"type=CONFIG_CHANGE\b.*\baudit_enabled=0\b",
         "Audit logging was disabled. Normal only during shutdown/maintenance.", mitre=["T1562.001"]),

    # ── system health (NOT security — kept separate on purpose) ──
    rule("disk-full", "Disk full", "high", "system-health", ["any"],
         r"No space left on device",
         "A filesystem is full. Try:  mk-logs.py --cleanup"),
    rule("disk-io-error", "Disk / filesystem error", "high", "system-health", ["kern", "syslog"],
         r"Buffer I/O error|blk_update_request: I/O error|EXT4-fs error|"
         r"XFS \([^)]*\): (?:Metadata corruption|I/O error|Corruption)|Remounting filesystem read-only|"
         r"ata\d+\.\d+: (?:failed command|exception)|critical medium error",
         "Hardware or filesystem trouble. Check SMART data and back up."),
    rule("kernel-panic", "Kernel panic / oops", "high", "system-health", ["kern", "syslog"],
         r"Kernel panic - not syncing|BUG: unable to handle kernel",
         "The kernel crashed."),
    rule("oom-kill", "Out-of-memory kill", "low", "system-health", ["kern", "syslog"],
         r"Out of memory: Killed process \d+ \((?P<proc>[^)]+)\)|invoked oom-killer",
         "The kernel killed a process to survive memory pressure."),
    rule("segfault", "Process segfault", "low", "system-health", ["kern", "syslog"],
         r"\bsegfault at [0-9a-f]+ ip [0-9a-f]+ sp [0-9a-f]+ error \d+ in (?P<proc>\S+)",
         "A program crashed. Often just a bug."),
    rule("service-failed", "systemd service failed", "low", "system-health", ["syslog"],
         r"systemd\[1\]: (?P<unit>\S+?\.service): Failed with result '(?P<result>[^']+)'",
         "A service stopped unexpectedly."),

    # ── informational ────────────────────────────────────────
    rule("dpkg-install", "Package installed", "info", "system-health", ["dpkg"],
         r"^\S+ \S+ install (?P<pkg>\S+) ",
         "Package installs in the window (use --min-severity info to list)."),
]

# ── log sources: (category, label, [paths/globs]) ────────────
LOG_SOURCES = [
    ("auth", "Auth / login", ["/var/log/auth.log", "/var/log/secure"]),
    ("syslog", "System", ["/var/log/syslog", "/var/log/messages"]),
    ("kern", "Kernel", ["/var/log/kern.log"]),
    ("ufw", "Firewall (UFW)", ["/var/log/ufw.log"]),
    ("fail2ban", "Fail2Ban", ["/var/log/fail2ban.log"]),
    ("cron", "Cron", ["/var/log/cron.log", "/var/log/cron"]),
    ("dpkg", "Package installs", ["/var/log/dpkg.log"]),
    ("rkhunter", "rkhunter", ["/var/log/rkhunter.log"]),
    ("chkrootkit", "chkrootkit", ["/var/log/chkrootkit.log"]),
    ("web", "Web server", ["/var/log/nginx/access.log", "/var/log/nginx/*access*.log",
                           "/var/log/apache2/access.log", "/var/log/apache2/*access*.log",
                           "/var/log/httpd/access_log", "/var/log/httpd/*access*log"]),
    ("audit", "auditd", ["/var/log/audit/audit.log"]),
    ("shell", "Shell history", ["/root/.bash_history", "/root/.zsh_history",
                                "/home/*/.bash_history", "/home/*/.zsh_history"]),
]
JOURNAL_FALLBACK_CATS = ["auth", "syslog", "kern", "cron"]
ROTATED_SUFFIX = re.compile(r"^(?:\.\d+|-\d{8})(?:\.(?:gz|bz2|xz))?$")
ROOT = ""   # --root prefix for analysing a mounted filesystem


def rp(path):
    return os.path.join(ROOT, path.lstrip("/")) if ROOT else path


def guess_cat(path):
    full = path.lower()
    n = os.path.basename(full)
    if "auth.log" in n or n.startswith("secure"):
        return "auth"
    for key, cat in (("audit", "audit"), ("ufw", "ufw"), ("fail2ban", "fail2ban"),
                     ("kern", "kern"), ("cron", "cron"), ("dpkg", "dpkg"),
                     ("rkhunter", "rkhunter"), ("chkrootkit", "chkrootkit"),
                     ("history", "shell")):
        if key in full:
            return cat
    if any(k in full for k in ("nginx", "apache", "httpd", "access")):
        return "web"
    if "syslog" in n or "messages" in n:
        return "syslog"
    return None   # unknown -> apply every rule


# ══════════════════════════════════════════════════════════════
#  TIMESTAMP PARSING
# ══════════════════════════════════════════════════════════════
_MON = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_RE_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,]\d+)?\s*(Z|[+-]\d\d:?\d\d)?")
_RE_SYS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\b")
_RE_CLF = re.compile(r"\[(\d{1,2})/([A-Z][a-z]{2})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-]\d{4})\]")
_RE_AUD = re.compile(r"msg=audit\((\d{9,11})(?:\.\d+)?:\d+\)")
_RE_HIST = re.compile(r"^#(\d{9,11})$")


def _tz(s):
    if not s:
        return None
    if s == "Z":
        return timezone.utc
    sign = -1 if s[0] == "-" else 1
    s = s[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(s[:2]), minutes=int(s[2:])))


def parse_ts(line, now, year=None):
    """Return a naive local datetime for the line, or None."""
    m = _RE_ISO.match(line)
    if m:
        try:
            y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
            dt = datetime(y, mo, d, h, mi, s)
        except ValueError:
            return None
        tz = _tz(m.group(7))
        if tz:
            dt = dt.replace(tzinfo=tz).astimezone().replace(tzinfo=None)
        return dt
    m = _RE_SYS.match(line)
    if m:
        mon = _MON.get(m.group(1))
        if not mon:
            return None
        yr = year or now.year
        try:
            dt = datetime(yr, mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
            if not year and dt > now + timedelta(days=1):   # Dec log read in Jan
                dt = dt.replace(year=yr - 1)
        except ValueError:
            return None
        return dt
    head = line[:160]
    m = _RE_CLF.search(head)
    if m:
        mon = _MON.get(m.group(2))
        if not mon:
            return None
        try:
            dt = datetime(int(m.group(3)), mon, int(m.group(1)), int(m.group(4)),
                          int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
        tz = _tz(m.group(7))
        return dt.replace(tzinfo=tz).astimezone().replace(tzinfo=None) if tz else dt
    m = _RE_AUD.search(line)
    if m:
        try:
            return datetime.fromtimestamp(int(m.group(1)))
        except (ValueError, OSError):
            return None
    m = _RE_HIST.match(line)
    if m:
        try:
            return datetime.fromtimestamp(int(m.group(1)))
        except (ValueError, OSError):
            return None
    return None


# ══════════════════════════════════════════════════════════════
#  READING LOGS (tail-first, gz/bz2/xz aware)
# ══════════════════════════════════════════════════════════════
def _count_newlines(f, upto):
    f.seek(0)
    total, left = 0, upto
    while left > 0:
        chunk = f.read(min(1 << 20, left))
        if not chunk:
            break
        total += chunk.count(b"\n")
        left -= len(chunk)
    return total


def read_log(path, max_bytes):
    """Return (lines, first_lineno, truncated, error). Reads the END of big files."""
    try:
        if not os.path.exists(path):
            return None, 1, False, "not found"
        if os.path.isdir(path):
            return None, 1, False, "is a directory"
        if not os.access(path, os.R_OK):
            return None, 1, False, "permission denied (run with sudo)"
        if os.path.getsize(path) == 0:
            return None, 1, False, "empty"
        first, truncated = 1, False
        opener = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}.get(
            os.path.splitext(path)[1].lower())
        if opener:
            with opener(path, "rb") as f:
                data = f.read(max_bytes * 4 + 1)
            if len(data) > max_bytes * 4:
                truncated, data = True, data[:max_bytes * 4]
        else:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                start = max(0, size - max_bytes)
                if start:
                    truncated = True
                    k = _count_newlines(f, start)
                    f.seek(start)
                    data = f.read()
                    nl = data.find(b"\n")
                    if nl != -1:
                        data = data[nl + 1:]
                    first = k + 2
                else:
                    data = f.read()
        text = data.decode("utf-8", errors="replace").replace("\r", "")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        return lines, first, truncated, None
    except Exception as e:  # noqa: BLE001
        return None, 1, False, str(e)


# ══════════════════════════════════════════════════════════════
#  RULES: load / merge / compile
# ══════════════════════════════════════════════════════════════
class Rule:
    __slots__ = ("id", "name", "sev", "rank", "category", "sources", "rx", "ex",
                 "event", "mitre", "desc")


def compile_rules(raw_rules, warn):
    out = []
    for r in raw_rules:
        if not isinstance(r, dict):
            warn(f"ignored a rule entry that is not a mapping: {r!r}")
            continue
        if not r.get("enabled", True):
            continue
        rid, pat = r.get("id"), r.get("pattern")
        if not rid or not pat:
            warn(f"rule {rid or '?'} skipped: needs both 'id' and 'pattern'")
            continue
        sev = str(r.get("severity", "low")).lower()
        if sev not in SEV_RANK:
            warn(f"rule {rid}: unknown severity '{sev}', using 'low'")
            sev = "low"
        flags = re.I if r.get("ignorecase", True) else 0
        try:
            rx = re.compile(pat, flags)
            ex = re.compile(r["exclude"], flags) if r.get("exclude") else None
        except re.error as e:
            warn(f"rule {rid} skipped: bad regex ({e})")
            continue
        srcs = r.get("sources") or ["any"]
        mitre = r.get("mitre") or []
        ru = Rule()
        ru.id, ru.name, ru.sev, ru.rank = rid, r.get("name", rid), sev, SEV_RANK[sev]
        ru.category = r.get("category", "general")
        ru.sources = set([srcs] if isinstance(srcs, str) else srcs)
        ru.rx, ru.ex, ru.event = rx, ex, r.get("event")
        ru.mitre = [mitre] if isinstance(mitre, str) else list(mitre)
        ru.desc = r.get("description", "")
        out.append(ru)
    return out


def load_rules_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        die(f"cannot read rules file: {e}")
    if path.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError as e:
            die(f"invalid JSON in {path}: {e}")
    else:
        try:
            import yaml
        except ImportError:
            die("YAML rules need PyYAML:  pip install pyyaml   (or use a .json rules file)")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            die(f"invalid YAML in {path}: {e}")
    if isinstance(data, dict):
        data = data.get("rules", [])
    if not isinstance(data, list):
        die(f"{path}: expected a list of rules (or a 'rules:' key)")
    return data


def merge_rules(base, custom):
    """Custom rules override built-ins by id (partial overrides OK), new ids are appended."""
    merged = {r["id"]: dict(r) for r in base}
    order = [r["id"] for r in base]
    for r in custom:
        if not isinstance(r, dict) or "id" not in r:
            continue
        if r["id"] in merged:
            merged[r["id"]].update(r)
        else:
            merged[r["id"]] = dict(r)
            order.append(r["id"])
    return [merged[i] for i in order]


def dump_rules(fmt):
    if fmt == "json":
        print(json.dumps({"rules": DEFAULT_RULES}, indent=2))
        return
    try:
        import yaml
    except ImportError:
        die("PyYAML not installed. Use  --dump-rules json  or  pip install pyyaml")
    print("# MK-logs detection rules (edit freely, then run:  mk-logs.py --rules rules.yaml)\n"
          "# - a rule with the same 'id' as a built-in OVERRIDES it (partial overrides work)\n"
          "# - set 'enabled: false' to disable a built-in rule\n"
          "# - severity: info | low | medium | high | critical\n"
          "# - sources: auth syslog kern ufw fail2ban cron dpkg rkhunter chkrootkit web audit shell any\n"
          "# - 'event' (auth_fail, auth_success, fw_block, web_404, web_authfail, banned) feeds the\n"
          "#   correlation engine; use named groups (?P<ip>..) (?P<user>..) to extract fields\n")
    print(yaml.safe_dump({"rules": DEFAULT_RULES}, sort_keys=False, width=10000,
                         allow_unicode=True, default_flow_style=False))


# ══════════════════════════════════════════════════════════════
#  ALLOWLIST
# ══════════════════════════════════════════════════════════════
class Allow:
    def __init__(self, path=None):
        self.nets, self.rx = [], []
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                for raw in f:
                    s = raw.strip()
                    if not s or s.startswith("#"):
                        continue
                    if s.lower().startswith("ip:"):
                        try:
                            self.nets.append(ipaddress.ip_network(s[3:].strip(), strict=False))
                        except ValueError:
                            print(c(f"  [!] allowlist: bad ip/cidr '{s}'", "yellow"), file=sys.stderr)
                    else:
                        try:
                            self.rx.append(re.compile(s, re.I))
                        except re.error:
                            print(c(f"  [!] allowlist: bad regex '{s}'", "yellow"), file=sys.stderr)
        except OSError as e:
            die(f"cannot read allowlist: {e}")

    def line(self, text):
        return any(r.search(text) for r in self.rx)

    def ip(self, value):
        if not self.nets:
            return False
        try:
            a = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(a in n for n in self.nets)


def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fe80::/10", "fc00::/7")]


def is_private(s):
    """True only for RFC1918 / loopback / link-local / ULA (not documentation ranges)."""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _INTERNAL_NETS)


# ══════════════════════════════════════════════════════════════
#  ENGINE
# ══════════════════════════════════════════════════════════════
MAX_STORED_PER_RULE = 2000


class Engine:
    def __init__(self, rules, args, allow, now, cutoff):
        self.rules, self.args, self.allow = rules, args, allow
        self.now, self.cutoff = now, cutoff
        self.min_rank = SEV_RANK[args.min_severity]
        self.max_bytes = int(args.max_mb * 1024 * 1024)
        self.findings = []                     # stored hits (capped per rule)
        self.corr = []                         # correlated detections
        self.events = defaultdict(list)
        self.rule_count = Counter()
        self.rule_first, self.rule_last = {}, {}
        self.stats = []
        self.seen = {}
        self._cache = {}
        self.extras = {}

    def rules_for(self, cats):
        key = None if cats is None else frozenset(cats)
        if key not in self._cache:
            if cats is None:
                self._cache[key] = list(self.rules)
            else:
                self._cache[key] = [r for r in self.rules if "any" in r.sources or r.sources & set(cats)]
        return self._cache[key]

    # ── scan a block of lines ────────────────────────────────
    def scan_lines(self, lines, first_lineno, source, cats, st):
        rules = self.rules_for(cats)
        cur_ok, last_ts = True, None
        in_win = 0
        outside = 0
        for idx, line in enumerate(lines):
            if not line.strip():
                continue
            ts = parse_ts(line, self.now, self.args.year)
            if ts is not None:
                last_ts = ts
                cur_ok = self.cutoff is None or ts >= self.cutoff
            if not cur_ok:
                outside += 1
                continue
            in_win += 1
            if self.allow.line(line):
                continue
            dup = None
            event_done = False
            for r in rules:
                m = r.rx.search(line)
                if not m or (r.ex and r.ex.search(line)):
                    continue
                g = {k: v for k, v in m.groupdict().items() if v}
                ip = g.get("ip")
                if ip:
                    if not valid_ip(ip):
                        g.pop("ip")
                    elif self.allow.ip(ip):
                        continue
                if dup is None:
                    h = hash(line)
                    owner = self.seen.get(h)
                    if owner is None:
                        self.seen[h] = source
                        dup = False
                    else:
                        dup = owner != source
                if dup:
                    break
                when = ts or last_ts
                if r.event and not event_done:
                    event_done = True
                    self.events[r.event].append(
                        {"ts": when, "source": source, "lineno": first_lineno + idx, "line": line, "g": g})
                self.rule_count[r.id] += 1
                self.rule_first.setdefault(r.id, when)
                self.rule_last[r.id] = when
                if r.rank >= self.min_rank and self.rule_count[r.id] <= MAX_STORED_PER_RULE:
                    self.findings.append({
                        "rule": r.id, "name": r.name, "severity": r.sev, "category": r.category,
                        "mitre": r.mitre, "source": source, "lineno": first_lineno + idx,
                        "ts": when, "line": line.strip()[:400], "g": g})
        st["lines"] = len(lines)
        st["in_window"] = in_win
        st["outside_window"] = outside

    def scan_path(self, path, cat, label):
        st = {"path": path, "category": cat or "auto", "label": label,
              "lines": 0, "in_window": 0, "error": None, "note": None}
        self.stats.append(st)
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
        except OSError:
            st["error"] = "not found"
            return
        if self.cutoff and cat != "shell" and mtime < self.cutoff:
            st["note"] = f"no entries in window (last modified {mtime:%Y-%m-%d %H:%M})"
            return
        lines, first, trunc, err = read_log(path, self.max_bytes)
        if err:
            st["error"] = err
            return
        st["truncated"] = trunc
        self.scan_lines(lines, first, path, {cat} if cat else None, st)

    def scan_journal(self, cats):
        st = {"path": "journald", "category": "journal", "label": "journald (fallback)",
              "lines": 0, "in_window": 0, "error": None, "note": None}
        self.stats.append(st)
        cmd = ["journalctl", "--no-pager", "-q", "-o", "short-iso"]
        cmd += ["--since", self.cutoff.strftime("%Y-%m-%d %H:%M:%S")] if self.cutoff else ["-n", "200000"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except FileNotFoundError:
            st["error"] = "journalctl not found"
            return
        except subprocess.TimeoutExpired:
            st["error"] = "journalctl timed out"
            return
        if not res.stdout.strip():
            st["error"] = "no journal output (need root or systemd-journal group?)"
            return
        self.scan_lines(res.stdout.split("\n"), 1, "journald", set(cats), st)

    def fallback_lastb(self):
        """When there is no auth log: build auth_fail events from btmp."""
        try:
            res = subprocess.run(["lastb", "-F", "-i", "-w"], capture_output=True, text=True, timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        n = 0
        for line in res.stdout.split("\n"):
            m = _LAST_RE.match(line)
            if not m or not valid_ip(m.group("ip")):
                continue
            ts = _last_ts(m.group("ts"))
            if self.cutoff and ts and ts < self.cutoff:
                continue
            if self.allow.ip(m.group("ip")):
                continue
            self.events["auth_fail"].append({"ts": ts, "source": "lastb", "lineno": None,
                                             "line": line.strip(),
                                             "g": {"ip": m.group("ip"), "user": m.group("user")}})
            n += 1
        if n:
            self.stats.append({"path": "btmp (lastb)", "category": "auth", "label": "Failed logins (btmp)",
                               "lines": n, "in_window": n, "error": None, "note": None})

    # ── correlation ──────────────────────────────────────────
    def _add_corr(self, rid, name, sev, mitre, detail, ts, ip=None, user=None):
        self.corr.append({"rule": rid, "name": name, "severity": sev, "mitre": mitre,
                          "detail": detail, "ts": ts, "ip": ip, "user": user})

    def correlate(self):
        a = self.args
        win = timedelta(minutes=a.window)
        saf_win = timedelta(minutes=a.saf_window)
        key = lambda e: e["ts"] or datetime.min  # noqa: E731

        # brute force + password spraying (per source IP)
        fails = sorted(self.events["auth_fail"], key=key)
        by_ip = defaultdict(list)
        for e in fails:
            if e["g"].get("ip"):
                by_ip[e["g"]["ip"]].append(e)
        for ip, es in by_ip.items():
            times = [key(e) for e in es]
            cnt, t0, t1 = _sliding_count(times, win)
            if cnt >= a.threshold:
                users = Counter(e["g"].get("user", "?") for e in es).most_common(3)
                ulist = ", ".join(f"{u}×{n}" for u, n in users)
                sev = "high" if cnt >= a.threshold * 5 else "medium"
                self._add_corr("corr-brute-force", "SSH brute force", sev, ["T1110.001"],
                               f"{ip}: {cnt} failed logins within {a.window}m "
                               f"({_fmt(t0)} → {_fmt(t1)}); {len(es)} total failures; top users: {ulist}",
                               t1, ip=ip)
            users_seq = [e["g"].get("user") for e in es]
            dmax, t0, t1 = _sliding_distinct(times, users_seq, win)
            if dmax >= a.spray_users:
                self._add_corr("corr-password-spray", "Password spraying / username sweep", "high",
                               ["T1110.003"],
                               f"{ip}: {dmax} different usernames tried within {a.window}m "
                               f"({_fmt(t0)} → {_fmt(t1)})", t1, ip=ip)

        # success after failure
        fail_times = {ip: [key(e) for e in es] for ip, es in by_ip.items()}
        reported = set()
        for s in sorted(self.events["auth_success"], key=key):
            ip, user = s["g"].get("ip"), s["g"].get("user", "?")
            if not ip or ip not in fail_times or (ip, user) in reported:
                continue
            t = key(s)
            ft = fail_times[ip]
            cnt = bisect.bisect_right(ft, t) - bisect.bisect_left(ft, t - saf_win)
            if cnt >= a.threshold:
                reported.add((ip, user))
                priv = is_private(ip)
                self._add_corr("corr-success-after-failure", "Successful login after repeated failures",
                               "high" if priv else "critical", ["T1110.001", "T1078"],
                               f"{ip} logged in as '{user}' at {_fmt(t)} after {cnt} failures in the "
                               f"previous {a.saf_window}m" + (" (internal IP)" if priv else
                                                              " — possible compromised account"),
                               t, ip=ip, user=user)

        # port scan from firewall blocks
        blocks = sorted(self.events["fw_block"], key=key)
        bp = defaultdict(list)
        for e in blocks:
            if e["g"].get("ip") and e["g"].get("dport"):
                bp[e["g"]["ip"]].append(e)
        for ip, es in bp.items():
            dmax, t0, t1 = _sliding_distinct([key(e) for e in es], [e["g"]["dport"] for e in es], win)
            if dmax >= a.scan_ports:
                self._add_corr("corr-port-scan", "Port scan", "high" if dmax >= a.scan_ports * 5 else "medium",
                               ["T1595"],
                               f"{ip}: {dmax} different ports probed within {a.window}m "
                               f"({_fmt(t0)} → {_fmt(t1)})", t1, ip=ip)

        # web scanning / web brute force
        for etype, rid, name, mitre, thr in (
                ("web_404", "corr-web-scan", "Web scanning (many 404s)", ["T1595.002"], a.web_threshold),
                ("web_authfail", "corr-web-brute-force", "Web login brute force", ["T1110"], a.threshold)):
            wb = defaultdict(list)
            for e in sorted(self.events[etype], key=key):
                if e["g"].get("ip"):
                    wb[e["g"]["ip"]].append(key(e))
            for ip, times in wb.items():
                cnt, t0, t1 = _sliding_count(times, win)
                if cnt >= thr:
                    self._add_corr(rid, name, "medium", mitre,
                                   f"{ip}: {cnt} hits within {a.window}m ({_fmt(t0)} → {_fmt(t1)})",
                                   t1, ip=ip)
        self.corr.sort(key=lambda x: -SEV_RANK[x["severity"]])

    # ── Top-N ────────────────────────────────────────────────
    def top(self, n):
        ev = self.events
        t = {}
        t["failed_ips"] = Counter(e["g"]["ip"] for e in ev["auth_fail"] if e["g"].get("ip")).most_common(n)
        t["failed_users"] = Counter(e["g"]["user"] for e in ev["auth_fail"] if e["g"].get("user")).most_common(n)
        t["logins"] = Counter(f"{e['g'].get('user', '?')} from {e['g'].get('ip', '?')}"
                              for e in ev["auth_success"]).most_common(n)
        t["fw_ips"] = Counter(e["g"]["ip"] for e in ev["fw_block"] if e["g"].get("ip")).most_common(n)
        t["bans"] = Counter(e["g"]["ip"] for e in ev["banned"] if e["g"].get("ip")).most_common(n)
        t["web_ips"] = Counter(f["g"]["ip"] for f in self.findings
                               if f["category"] == "web" and f["g"].get("ip")
                               and SEV_RANK[f["severity"]] >= SEV_RANK["low"]).most_common(n)
        names = {r.id: r.name for r in self.rules}
        t["rules"] = [(names.get(k, k), v) for k, v in self.rule_count.most_common(n)
                      if SEV_RANK[next((r.sev for r in self.rules if r.id == k), "low")] >= self.min_rank]
        buckets = Counter()
        stamped = [e["ts"] for e in ev["auth_fail"] if e["ts"]]
        if stamped:
            span = max(stamped) - min(stamped)
            fmt = "%m-%d %H:00" if span <= timedelta(hours=72) else "%Y-%m-%d"
            for ts in stamped:
                buckets[ts.strftime(fmt)] += 1
        t["fail_timeline"] = sorted(buckets.items())
        return t


# ── sliding-window helpers ───────────────────────────────────
def _sliding_count(times, window):
    best, j = (0, None, None), 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, times[j], t)
    return best


def _sliding_distinct(times, keys, window):
    best, j = (0, None, None), 0
    live = Counter()
    for i, t in enumerate(times):
        live[keys[i]] += 1
        while t - times[j] > window:
            live[keys[j]] -= 1
            if live[keys[j]] == 0:
                del live[keys[j]]
            j += 1
        if len(live) > best[0]:
            best = (len(live), times[j], t)
    return best


def _fmt(dt):
    return "unknown time" if dt is None or dt == datetime.min else dt.strftime("%Y-%m-%d %H:%M:%S")


# ── last / lastb parsing ─────────────────────────────────────
_LAST_RE = re.compile(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<ip>\S+)\s+"
                      r"(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+ \d\d:\d\d:\d\d \d{4})")


def _last_ts(s):
    try:
        return datetime.strptime(re.sub(r"\s+", " ", s), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def recent_logins(cutoff, limit=40):
    try:
        res = subprocess.run(["last", "-F", "-i", "-w", "-n", "200"], capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    rows = []
    for line in res.stdout.split("\n"):
        m = _LAST_RE.match(line)
        if not m:
            continue
        ts = _last_ts(m.group("ts"))
        if cutoff and ts and ts < cutoff:
            continue
        rows.append({"user": m.group("user"), "tty": m.group("tty"), "ip": m.group("ip"),
                     "ts": ts, "raw": line.strip()})
        if len(rows) >= limit:
            break
    return rows


# ══════════════════════════════════════════════════════════════
#  DISCOVERY + SCAN DRIVER
# ══════════════════════════════════════════════════════════════
def discover(args, cutoff):
    plan, seen_real = [], set()

    def add(cat, label, path):
        real = os.path.realpath(path)
        if real in seen_real:
            return
        seen_real.add(real)
        plan.append((cat, label, path))

    for cat, label, patterns in LOG_SOURCES:
        for pat in patterns:
            for path in sorted(glob.glob(rp(pat))):
                if not os.path.isfile(path):
                    continue
                add(cat, label, path)
                if args.rotated and cat != "shell":
                    for q in sorted(glob.glob(glob.escape(path) + "*")):
                        suffix = q[len(path):]
                        if q != path and ROTATED_SUFFIX.match(suffix):
                            add(cat, label + " (rotated)", q)
    return plan


def run_scan(args, rules, allow):
    now = datetime.now()
    hours = args.hours_eff
    cutoff = now - timedelta(hours=hours) if hours else None
    eng = Engine(rules, args, allow, now, cutoff)
    live = not ROOT and not args.file

    if args.file:
        for f in args.file:
            cat = args.type if args.type and args.type != "auto" else guess_cat(f)
            eng.scan_path(f, cat, os.path.basename(f))
    else:
        for cat, label, path in discover(args, cutoff):
            eng.scan_path(path, cat, label)
        readable = {s["category"] for s in eng.stats if not s["error"]}
        if live:
            missing = [cat for cat in JOURNAL_FALLBACK_CATS if cat not in readable]
            if missing:
                eng.scan_journal(missing)
            if "auth" not in readable:
                eng.fallback_lastb()

    eng.correlate()
    if live:
        eng.extras["logins"] = recent_logins(cutoff)
    return eng


# ══════════════════════════════════════════════════════════════
#  REPORT BUILD + RENDER
# ══════════════════════════════════════════════════════════════
def iso(dt):
    return dt.isoformat(timespec="seconds") if isinstance(dt, datetime) and dt != datetime.min else None


def build_report(eng):
    a = eng.args
    meta = {r.id: r for r in eng.rules}
    by_rule = defaultdict(list)
    for f in eng.findings:
        by_rule[f["rule"]].append(f)
    groups = []
    for rid, items in by_rule.items():
        r = meta[rid]
        groups.append({
            "rule": rid, "name": r.name, "severity": r.sev, "category": r.category,
            "mitre": r.mitre, "description": r.desc, "count": eng.rule_count[rid],
            "first": eng.rule_first.get(rid), "last": eng.rule_last.get(rid), "items": items})
    groups.sort(key=lambda g: (-SEV_RANK[g["severity"]], -g["count"]))

    counts = Counter()
    for g in groups:
        counts[g["severity"]] += 1
    for cdet in eng.corr:
        counts[cdet["severity"]] += 1
    worst = max([SEV_RANK[k] for k, v in counts.items() if v and SEV_RANK[k] >= SEV_RANK["low"]] or [-1])
    return {"groups": groups, "counts": counts, "worst": worst,
            "top": eng.top(a.top), "corr": eng.corr}


def housekeeping_notes():
    if ROOT:
        return []
    notes = []
    try:
        du = shutil.disk_usage("/var")
        pct = du.used / du.total * 100
        if pct >= 80:
            notes.append(f"/var is {pct:.0f}% full ({human(du.free)} free)")
    except OSError:
        pass
    try:
        out = subprocess.run(["du", "-sk", "/var/log"], capture_output=True, text=True, timeout=30).stdout
        kb = int(out.split()[0])
        if kb > 1024 * 1024:
            notes.append(f"/var/log is {human(kb * 1024)}")
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        pass
    return notes


def human(n):
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


def _bar(v, vmax, width=28):
    return "█" * max(1, round(v / vmax * width)) if vmax else ""


def _trim(s, n=170):
    return s if len(s) <= n else s[:n - 1] + "…"


def render_text(eng, rep):
    a = eng.args
    out = []
    P = out.append
    hours = a.hours_eff
    window = f"last {hours}h" if hours else "all time"
    P("")
    P(c("══ SCAN ══", "bold", "cyan"))
    P(f"  Host: {socket.gethostname()}   Window: {window}   "
      f"Rules: {len(eng.rules)}   Min severity: {a.min_severity}")
    scanned = [s for s in eng.stats if not s["error"] and not s.get("note")]
    for s in scanned:
        extra = " (tail only)" if s.get("truncated") else ""
        P(c(f"  ✔ {s['path']}  — {s['in_window']} lines in window / {s['lines']} read{extra}", "dim"))
    for s in eng.stats:
        if s.get("note"):
            P(c(f"  – {s['path']}  — {s['note']}", "dim"))
    perm = [s for s in eng.stats if s["error"] and "permission" in s["error"]]
    for s in perm:
        P(c(f"  ✘ {s['path']} — {s['error']}", "yellow"))
    for s in eng.stats:
        if s["error"] and "permission" not in s["error"] and s["error"] != "empty":
            P(c(f"  ✘ {s['path']} — {s['error']}", "yellow"))
    if not scanned:
        P(c("  [!] No readable logs found. Run with sudo, or point at a file with --file.", "yellow"))
    tracked_old = sum(s.get("outside_window", 0) for s in eng.stats)
    if tracked_old and not any(s["in_window"] for s in eng.stats):
        P(c(f"  [!] {tracked_old} lines were older than the window. Use --hours 0 to analyze all time.", "yellow"))
    if any(s["category"] == "shell" for s in scanned):
        P(c("  note: shell history has no timestamps, so the time window doesn't apply to it", "dim"))

    # verdict
    P("")
    P(c("══ SUMMARY ══", "bold", "cyan"))
    cnt = rep["counts"]
    parts = [c(f"{cnt[s]} {s.upper()}", *SEV_STYLE[s]) for s in reversed(SEVERITIES[1:]) if cnt[s]]
    if rep["worst"] < 0:
        P("  " + c("[✔] No findings at or above 'low' — nothing notable in this window.", "green"))
    else:
        P("  Detections: " + "  ·  ".join(parts))
        verdict = {4: ("CRITICAL — act now: likely compromise indicators", "bold", "magenta"),
                   3: ("HIGH — investigate soon", "red"),
                   2: ("MEDIUM — review when you can", "yellow"),
                   1: ("LOW — routine noise, glance through it", "cyan")}[rep["worst"]]
        P("  Verdict:    " + c(verdict[0], *verdict[1:]))

    # correlated
    if rep["corr"]:
        P("")
        P(c("══ CORRELATED DETECTIONS ══", "bold", "cyan"))
        for d in rep["corr"]:
            P(f"  {sev_tag(d['severity'])} {c(d['name'], 'bold')}")
            P(f"      {d['detail']}")
            P(c("      ATT&CK: " + "; ".join(mitre_label(m) for m in d["mitre"]), "dim"))

    # findings
    def render_groups(groups):
        for g in groups:
            hdr = f"  {sev_tag(g['severity'])} {c(g['name'], 'bold')} — {g['count']} hit{'s' if g['count'] != 1 else ''}"
            P("")
            P(hdr)
            if g["description"]:
                P(c(f"      why: {g['description']}", "dim"))
            if g["mitre"]:
                P(c("      ATT&CK: " + "; ".join(mitre_label(m) for m in g["mitre"]), "dim"))
            if g["first"] and g["last"]:
                P(c(f"      first: {_fmt(g['first'])}   last: {_fmt(g['last'])}", "dim"))
            for it in g["items"][:a.samples]:
                loc = os.path.basename(it["source"]) + (f":L{it['lineno']}" if it["lineno"] else "")
                P(f"      {c(loc, 'dim')}  {_trim(it['line'])}")
            if g["count"] > a.samples:
                P(c(f"      … and {g['count'] - a.samples} more", "dim"))

    sec = [g for g in rep["groups"] if g["category"] != "system-health"]
    health = [g for g in rep["groups"] if g["category"] == "system-health"]
    if sec:
        P("")
        P(c("══ FINDINGS · SECURITY ══", "bold", "cyan"))
        render_groups(sec)
    if health:
        P("")
        P(c("══ FINDINGS · SYSTEM HEALTH (not security) ══", "bold", "cyan"))
        render_groups(health)

    # top-N
    t = rep["top"]

    def table(title, rows, fmt=lambda k: k):
        if not rows:
            return
        P("")
        P(c(f"  {title}", "bold"))
        vmax = rows[0][1]
        width = max(len(str(fmt(k))) for k, _ in rows)
        for k, v in rows:
            P(f"    {str(fmt(k)):<{width}}  {v:>6}  {c(_bar(v, vmax), 'cyan')}")

    def ipfmt(k):
        return f"{k} (internal)" if is_private(k) else k

    P("")
    P(c(f"══ TOP {a.top} ══", "bold", "cyan"))
    if not any(t[k] for k in ("failed_ips", "failed_users", "logins", "fw_ips", "bans", "web_ips")):
        P(c("  nothing to rank", "dim"))
    table("Failed logins by source IP", t["failed_ips"], ipfmt)
    table("Usernames targeted", t["failed_users"])
    table("Successful logins", t["logins"])
    table("Firewall blocks by source IP", t["fw_ips"], ipfmt)
    table("Fail2Ban bans", t["bans"], ipfmt)
    table("Web attackers (IPs with suspicious requests)", t["web_ips"], ipfmt)
    if t["fail_timeline"]:
        rows = t["fail_timeline"][-24:]
        P("")
        P(c("  Failed logins over time", "bold"))
        vmax = max(v for _, v in rows)
        for k, v in rows:
            P(f"    {k}  {v:>6}  {c(_bar(v, vmax), 'cyan')}")

    # logins
    logins = eng.extras.get("logins")
    if logins:
        P("")
        P(c("══ RECENT LOGINS (wtmp) ══", "bold", "cyan"))
        for row in logins[:15]:
            flag = c("  ← root", "yellow") if row["user"] == "root" else ""
            P(f"  {c(_fmt(row['ts']), 'dim')}  {row['user']:<12} {row['tty']:<10} {row['ip']}{flag}")

    notes = housekeeping_notes()
    if notes:
        P("")
        P(c("══ HOUSEKEEPING ══", "bold", "cyan"))
        for n in notes:
            P(c(f"  [!] {n}", "yellow"))
        P("  Run  sudo python3 mk-logs.py --cleanup  to see what's eating space and clear it safely.")
    P("")
    return "\n".join(out)


def _finding_dict(f):
    return {"rule": f["rule"], "name": f["name"], "severity": f["severity"], "category": f["category"],
            "mitre": f["mitre"], "source": f["source"], "lineno": f["lineno"], "timestamp": iso(f["ts"]),
            "ip": f["g"].get("ip"), "user": f["g"].get("user"), "line": f["line"]}


def render_json(eng, rep):
    a = eng.args
    doc = {
        "tool": "MK-logs", "version": VERSION, "host": socket.gethostname(),
        "generated": datetime.now().isoformat(timespec="seconds"),
        "window_hours": a.hours_eff or None,
        "settings": {"threshold": a.threshold, "window_min": a.window, "saf_window_min": a.saf_window,
                     "spray_users": a.spray_users, "scan_ports": a.scan_ports,
                     "web_threshold": a.web_threshold, "min_severity": a.min_severity},
        "sources": [{k: v for k, v in s.items()} for s in eng.stats],
        "summary": {s: rep["counts"][s] for s in SEVERITIES},
        "correlated": [{"rule": d["rule"], "name": d["name"], "severity": d["severity"],
                        "mitre": [{"id": m, "name": MITRE_NAMES.get(m)} for m in d["mitre"]],
                        "detail": d["detail"], "timestamp": iso(d["ts"]), "ip": d["ip"], "user": d["user"]}
                       for d in rep["corr"]],
        "findings": [{"rule": g["rule"], "name": g["name"], "severity": g["severity"],
                      "category": g["category"], "description": g["description"],
                      "mitre": [{"id": m, "name": MITRE_NAMES.get(m)} for m in g["mitre"]],
                      "count": g["count"], "first": iso(g["first"]), "last": iso(g["last"]),
                      "samples": [_finding_dict(i) for i in g["items"][:50]]} for g in rep["groups"]],
        "top": {k: ([{"key": x, "count": y} for x, y in v] if isinstance(v, list) else v)
                for k, v in rep["top"].items()},
    }
    return json.dumps(doc, indent=2, default=str)


def render_csv(eng, rep):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "rule", "name", "mitre", "source", "lineno", "timestamp", "ip", "user", "detail"])
    for d in rep["corr"]:
        w.writerow([d["severity"], d["rule"], d["name"], ";".join(d["mitre"]), "correlation", "",
                    iso(d["ts"]) or "", d["ip"] or "", d["user"] or "", d["detail"]])
    for g in rep["groups"]:
        for f in g["items"]:
            w.writerow([f["severity"], f["rule"], f["name"], ";".join(f["mitre"]), f["source"],
                        f["lineno"] or "", iso(f["ts"]) or "", f["g"].get("ip", ""),
                        f["g"].get("user", ""), f["line"]])
    return buf.getvalue()


def render_md(eng, rep):
    a = eng.args
    L = [f"# MK-logs report — {socket.gethostname()}", "",
         f"- Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
         f"- Window: {'last ' + str(a.hours_eff) + 'h' if a.hours_eff else 'all time'}",
         "- Detections: " + (", ".join(f"{rep['counts'][s]} {s}" for s in reversed(SEVERITIES[1:])
                                       if rep["counts"][s]) or "none"), ""]
    if rep["corr"]:
        L += ["## Correlated detections", ""]
        for d in rep["corr"]:
            L.append(f"- **[{d['severity'].upper()}] {d['name']}** — {d['detail']} "
                     f"(ATT&CK: {', '.join(mitre_label(m) for m in d['mitre'])})")
        L.append("")
    if rep["groups"]:
        L += ["## Findings", ""]
        for g in rep["groups"]:
            L.append(f"### [{g['severity'].upper()}] {g['name']} — {g['count']} hits")
            if g["description"]:
                L.append(f"_{g['description']}_")
            if g["mitre"]:
                L.append("ATT&CK: " + ", ".join(mitre_label(m) for m in g["mitre"]))
            L.append("")
            for it in g["items"][:a.samples]:
                loc = os.path.basename(it["source"]) + (f":L{it['lineno']}" if it["lineno"] else "")
                L.append(f"- `{loc}` {it['line'][:200]}")
            L.append("")
    t = rep["top"]
    for title, key in (("Failed logins by IP", "failed_ips"), ("Usernames targeted", "failed_users"),
                       ("Successful logins", "logins"), ("Firewall blocks by IP", "fw_ips"),
                       ("Web attackers", "web_ips")):
        if t[key]:
            L += [f"## Top: {title}", "", "| Item | Count |", "|---|---|"]
            L += [f"| {k} | {v} |" for k, v in t[key]]
            L.append("")
    return "\n".join(L)


# ══════════════════════════════════════════════════════════════
#  CLEANUP ASSISTANT
# ══════════════════════════════════════════════════════════════
ROTATED_FILE_RE = re.compile(
    r"(?:\.\d+(?:\.(?:gz|bz2|xz|zst))?|\.(?:gz|bz2|xz|zst)|\.old|-\d{8}(?:\.(?:gz|bz2|xz|zst))?)$")
ARCHIVE_DIR = "/var/log/mk-logs-archive"


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def _lsize(path):
    try:
        st = os.lstat(path)
        return st.st_blocks * 512
    except OSError:
        return 0


def find_rotated_logs(days):
    cutoff = datetime.now().timestamp() - days * 86400
    out = []
    base = rp("/var/log")
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        if os.path.abspath(dirpath).startswith(rp(ARCHIVE_DIR)):
            dirnames[:] = []
            continue
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not ROTATED_FILE_RE.search(fn):
                continue
            try:
                if os.lstat(p).st_mtime < cutoff:
                    out.append(p)
            except OSError:
                pass
    return out


def find_big_logs(min_mb=100):
    out = []
    base = rp("/var/log")
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        if os.path.abspath(dirpath).startswith(rp(ARCHIVE_DIR)) or "/journal" in dirpath:
            dirnames[:] = []
            continue
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or ROTATED_FILE_RE.search(fn):
                continue
            try:
                if os.lstat(p).st_size >= min_mb * 1024 * 1024:
                    out.append(p)
            except OSError:
                pass
    return out


def find_old_files(dirs, days):
    cutoff = datetime.now().timestamp() - days * 86400
    out = []
    for d in dirs:
        for dirpath, _dn, filenames in os.walk(rp(d), followlinks=False):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    if not os.path.islink(p) and os.lstat(p).st_mtime < cutoff:
                        out.append(p)
                except OSError:
                    pass
    return out


def journal_usage():
    if ROOT or not shutil.which("journalctl"):
        return None
    rc, text = _run(["journalctl", "--disk-usage"], 20)
    m = re.search(r"take up ([\d.]+)([KMGT]?)", text)
    if rc != 0 or not m:
        return None
    mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]
    return int(float(m.group(1)) * mult)


def dir_kb(path):
    rc, out = _run(["du", "-sk", path], 60)
    try:
        return int(out.split()[0]) * 1024 if rc == 0 else 0
    except (ValueError, IndexError):
        return 0


def disk_report():
    print(c("\n══ DISK USAGE ══", "bold", "cyan"))
    for mount in ("/", "/var"):
        try:
            du = shutil.disk_usage(rp(mount))
        except OSError:
            continue
        pct = du.used / du.total * 100
        style = "red" if pct >= 90 else "yellow" if pct >= 80 else "green"
        print(f"  {mount:<5} {c(f'{pct:4.0f}% used', style)}  ({human(du.used)} of {human(du.total)}, {human(du.free)} free)")
    rc, out = _run(["du", "-xk", "-d", "2", rp("/var")], 120)
    rows = []
    for line in out.split("\n"):
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].rstrip("/") != rp("/var").rstrip("/"):
            rows.append((int(parts[0]) * 1024, parts[1]))
    rows.sort(reverse=True)
    if rows:
        print(c("\n  Biggest things under /var:", "bold"))
        vmax = rows[0][0]
        for size, path in rows[:12]:
            print(f"    {human(size):>7}  {path:<44} {c(_bar(size, vmax, 20), 'cyan')}")


def build_candidates(days):
    cands = []

    rot = find_rotated_logs(days)
    if rot:
        cands.append({"title": f"Rotated / compressed logs older than {days} days",
                      "size": sum(_lsize(p) for p in rot), "files": rot, "kind": "files", "log": True,
                      "note": "Old archives such as syslog.3.gz. Active logs are never touched."})

    ju = journal_usage()
    if ju and ju > 50 * 1024 * 1024:
        cands.append({"title": f"systemd journal older than {days} days", "size": ju, "kind": "journal",
                      "log": True, "note": f"Runs: journalctl --vacuum-time={days}d  (size shown is current total)"})

    big = find_big_logs()
    if big:
        cands.append({"title": "Huge active logs (>100MB) — archive then empty", "size": sum(_lsize(p) for p in big),
                      "files": big, "kind": "archive", "log": True,
                      "note": f"Each log is gzipped into {ARCHIVE_DIR}/ first, then emptied in place. "
                              "A few lines written during the copy can be lost."})

    if shutil.which("apt-get") and os.path.isdir(rp("/var/cache/apt/archives")):
        sz = dir_kb(rp("/var/cache/apt/archives"))
        if sz > 20 * 1024 * 1024:
            cands.append({"title": "APT package cache", "size": sz, "kind": "cmd", "log": False,
                          "cmd": ["apt-get", "clean"], "note": "Downloaded .deb files. Safe: apt-get clean."})
        rc, sim = _run(["apt-get", "-s", "autoremove"], 60)
        pkgs = re.findall(r"^Remv (\S+)", sim, re.M)
        if pkgs:
            cands.append({"title": f"APT autoremove ({len(pkgs)} unused packages, incl. old kernels)",
                          "size": 0, "kind": "cmd", "log": False, "cmd": ["apt-get", "autoremove", "--purge", "-y"],
                          "note": "Would remove: " + ", ".join(pkgs[:6]) + (" …" if len(pkgs) > 6 else "")})
    for mgr in ("dnf", "yum"):
        if shutil.which(mgr) and os.path.isdir(rp(f"/var/cache/{mgr}")):
            sz = dir_kb(rp(f"/var/cache/{mgr}"))
            if sz > 20 * 1024 * 1024:
                cands.append({"title": f"{mgr.upper()} cache", "size": sz, "kind": "cmd", "log": False,
                              "cmd": [mgr, "clean", "all"], "note": f"Safe: {mgr} clean all."})
            break

    crash = find_old_files(["/var/crash", "/var/lib/systemd/coredump"], days)
    if crash:
        cands.append({"title": f"Crash dumps / coredumps older than {days} days",
                      "size": sum(_lsize(p) for p in crash), "files": crash, "kind": "files", "log": False,
                      "note": "Only needed if you're debugging a crash."})

    if shutil.which("docker") and os.path.isdir(rp("/var/lib/docker")) and not ROOT:
        rc, df = _run(["docker", "system", "df"], 30)
        cands.append({"title": "Docker: unused containers, images, networks, build cache", "size": 0,
                      "kind": "cmd", "log": False, "cmd": ["docker", "system", "prune", "-f"],
                      "note": "Volumes are NOT removed. Current usage:\n      " +
                              "\n      ".join(df.strip().split("\n")[:6]) if rc == 0 else
                              "Volumes are NOT removed. (docker daemon not reachable to show usage)",
                      "risky": True})
    return cands


def _archive_and_truncate(path):
    os.makedirs(ARCHIVE_DIR, mode=0o750, exist_ok=True)
    dest = os.path.join(ARCHIVE_DIR, f"{os.path.basename(path)}.{datetime.now():%Y%m%d-%H%M%S}.gz")
    with open(path, "rb") as src, gzip.open(dest, "wb", compresslevel=6) as dst:
        shutil.copyfileobj(src, dst)
    if not os.path.exists(dest) or os.path.getsize(dest) == 0:
        raise OSError("archive failed, original left untouched")
    with open(path, "r+b") as f:
        f.truncate(0)
    return dest


def _confirm(prompt, default=False):
    try:
        ans = input(f"  {prompt} {'[Y/n]' if default else '[y/N]'} ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes") if ans else default


def cleanup_assistant(args, evidence_risk=False):
    print(banner())
    disk_report()
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    dry = args.dry_run
    if not is_root and not dry and not ROOT:
        print(c("\n  [!] Not running as root — switching to DRY-RUN (nothing will be changed). "
                "Re-run with sudo to actually clean.", "yellow"))
        dry = True
    if ROOT and not dry:
        print(c("\n  [!] --root given: cleanup is dry-run only on mounted images.", "yellow"))
        dry = True

    print(c(f"\n  Scanning for safe-to-clean items (age threshold: {args.keep_days} days)…", "dim"))
    cands = build_candidates(args.keep_days)
    if not cands:
        print(c("\n  [✔] Nothing worth cleaning found.", "green"))
        return
    total = sum(x["size"] for x in cands)
    print(c("\n══ CLEANUP CANDIDATES ══", "bold", "cyan"))
    for i, x in enumerate(cands, 1):
        size = human(x["size"]) if x["size"] else "n/a"
        tag = c(" (log data)", "dim") if x.get("log") else ""
        risky = c("  ⚠ review first", "yellow") if x.get("risky") else ""
        print(f"\n  {c(f'[{i}]', 'bold')} {x['title']}{tag}{risky}")
        print(f"      reclaimable: {c(size, 'green')}")
        if x.get("note"):
            print(c(f"      {x['note']}", "dim"))
    print(f"\n  Total (where measurable): {c(human(total), 'green')}")
    if dry:
        print(c("  DRY-RUN: I'll show what would happen but change nothing.", "yellow"))
    if evidence_risk:
        print(c("\n  ⚠ This session found HIGH/CRITICAL detections. Logs are evidence — "
                "deleting them can destroy your ability to investigate.", "red"))

    try:
        sel = input(f"\n  {c('Pick items (e.g. 1,3), all, or q to quit:', 'cyan')} ").strip().lower()
    except EOFError:
        return
    if sel in ("", "q", "quit", "exit"):
        return
    chosen = list(range(len(cands))) if sel == "all" else \
        [int(x) - 1 for x in re.split(r"[,\s]+", sel) if x.isdigit() and 1 <= int(x) <= len(cands)]
    freed_total, ran = 0, False
    for i in chosen:
        x = cands[i]
        print(c(f"\n  ── {x['title']} ──", "bold"))
        if x["kind"] in ("files", "archive"):
            for p in x["files"][:8]:
                print(c(f"      {human(_lsize(p)):>7}  {p}", "dim"))
            if len(x["files"]) > 8:
                print(c(f"      … and {len(x['files']) - 8} more files", "dim"))
        elif x["kind"] == "cmd":
            print(c("      will run: " + " ".join(x["cmd"]), "dim"))
        elif x["kind"] == "journal":
            print(c(f"      will run: journalctl --vacuum-time={args.keep_days}d", "dim"))
        if evidence_risk and x.get("log"):
            try:
                ok = input(c("      Type DELETE to proceed anyway: ", "red")).strip() == "DELETE"
            except EOFError:
                ok = False
        else:
            ok = _confirm("Proceed?")
        if not ok:
            print(c("      skipped", "dim"))
            continue
        if dry:
            print(c("      [dry-run] no changes made", "yellow"))
            continue
        before = shutil.disk_usage("/var").free
        ran = True
        try:
            if x["kind"] == "files":
                n = 0
                for p in x["files"]:
                    try:
                        if os.path.islink(p) or not os.path.isfile(p):
                            continue
                        os.remove(p)
                        n += 1
                    except OSError as e:
                        print(c(f"      couldn't remove {p}: {e}", "yellow"))
                print(c(f"      removed {n} file(s)", "green"))
            elif x["kind"] == "archive":
                for p in x["files"]:
                    try:
                        dest = _archive_and_truncate(p)
                        print(c(f"      {p} → {dest}", "green"))
                    except OSError as e:
                        print(c(f"      {p}: {e}", "yellow"))
            elif x["kind"] == "journal":
                rc, out = _run(["journalctl", f"--vacuum-time={args.keep_days}d"], 120)
                print(c("      " + (out.strip().split("\n")[-1] if out.strip() else "done"),
                        "green" if rc == 0 else "yellow"))
            elif x["kind"] == "cmd":
                rc, out = _run(x["cmd"], 600)
                print(c(f"      exit {rc}", "green" if rc == 0 else "yellow"))
        except Exception as e:  # noqa: BLE001
            print(c(f"      failed: {e}", "red"))
            continue
        freed_total += max(0, shutil.disk_usage("/var").free - before)
    if ran and not dry:
        print(c(f"\n  [✔] Free space gained on /var: {human(freed_total)}", "green"))


# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════
def die(msg, code=2):
    print(c(f"[!] {msg}", "red"), file=sys.stderr)
    sys.exit(code)


def list_rules(rules):
    print(c(f"\n  {len(rules)} active rules   (export with --dump-rules, customize with --rules FILE)\n", "bold"))
    corr = [("corr-brute-force", "high/medium", "T1110.001", "Many failed logins from one IP in a window"),
            ("corr-password-spray", "high", "T1110.003", "Many different usernames from one IP"),
            ("corr-success-after-failure", "critical/high", "T1110.001 T1078",
             "A login succeeded after repeated failures from that IP"),
            ("corr-port-scan", "high/medium", "T1595", "One IP hitting many ports (firewall blocks)"),
            ("corr-web-scan", "medium", "T1595.002", "One IP generating many 404s"),
            ("corr-web-brute-force", "medium", "T1110", "One IP hammering login URLs")]
    for r in rules:
        srcs = ",".join(sorted(r.sources))
        print(f"  {sev_tag(r.sev)} {c(r.id, 'bold')}  {c(r.name, 'dim')}")
        print(c(f"      sources: {srcs}   ATT&CK: {' '.join(r.mitre) or '-'}", "dim"))
    print(c("\n  Built-in correlation detections (tune with --threshold/--window/etc.):", "bold"))
    for rid, sev, mt, desc in corr:
        print(f"  {c(rid, 'bold')}  [{sev}]  {c(desc, 'dim')}   {c(mt, 'dim')}")
    print()


def make_parser():
    p = argparse.ArgumentParser(
        prog="mk-logs.py", description="MK-logs v2 — Linux log analyzer with correlation & cleanup",
        epilog="Exit codes: 0 clean/low, 1 medium, 2 high/critical.")
    sc = p.add_argument_group("what to scan")
    sc.add_argument("--file", action="append", metavar="PATH", help="analyze this file (repeatable); default window = all time")
    sc.add_argument("--type", choices=["auto"] + [s[0] for s in LOG_SOURCES],
                    help="treat --file as this log type (default: guess from name)")
    sc.add_argument("--hours", type=float, help="lookback window in hours, 0 = all time (default 24; all time for --file)")
    sc.add_argument("--rotated", action="store_true", help="also read rotated logs (.1, .2.gz, -YYYYMMDD)")
    sc.add_argument("--root", metavar="DIR", help="treat DIR as / (analyze a mounted disk image or backup)")
    sc.add_argument("--max-mb", type=float, default=25, help="max MB read per file, from the END (default 25)")
    sc.add_argument("--year", type=int, help="assume this year for syslog timestamps (old log files)")
    dt = p.add_argument_group("detection tuning")
    dt.add_argument("--threshold", type=int, default=5, help="failures that count as brute force (default 5)")
    dt.add_argument("--window", type=int, default=10, help="correlation window in minutes (default 10)")
    dt.add_argument("--saf-window", type=int, default=60, help="minutes of history for success-after-failure (default 60)")
    dt.add_argument("--spray-users", type=int, default=5, help="distinct usernames = password spraying (default 5)")
    dt.add_argument("--scan-ports", type=int, default=15, help="distinct ports = port scan (default 15)")
    dt.add_argument("--web-threshold", type=int, default=50, help="404s in a window = web scan (default 50)")
    dt.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this (default low)")
    dt.add_argument("--rules", metavar="FILE", help="YAML/JSON rules: override or extend the built-ins")
    dt.add_argument("--no-builtin", action="store_true", help="use ONLY the rules from --rules")
    dt.add_argument("--allow", metavar="FILE", help="allowlist: regex per line, or 'ip: 10.0.0.0/8'")
    out = p.add_argument_group("output")
    out.add_argument("--format", choices=["text", "json", "csv", "md"], default="text")
    out.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    out.add_argument("--top", type=int, default=10, help="rows in Top-N tables (default 10)")
    out.add_argument("--samples", type=int, default=3, help="example lines per finding (default 3)")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("--quick", action="store_true", help="scan now, skip the menu")
    cl = p.add_argument_group("cleanup")
    cl.add_argument("--cleanup", action="store_true", help="disk usage report + guided cleanup of /var junk")
    cl.add_argument("--dry-run", action="store_true", help="with --cleanup: show only, change nothing")
    cl.add_argument("--keep-days", type=int, default=14, help="cleanup only touches items older than this (default 14)")
    ut = p.add_argument_group("utility")
    ut.add_argument("--list-rules", action="store_true")
    ut.add_argument("--dump-rules", nargs="?", const="yaml", choices=["yaml", "json"], help="print built-in rules")
    ut.add_argument("--version", action="version", version=f"MK-logs {VERSION}")
    return p


def prepare(args):
    global USE_COLOR, ROOT
    ROOT = os.path.abspath(args.root) if args.root else ""
    if args.root and not os.path.isdir(ROOT):
        die(f"--root {args.root} is not a directory")
    quiet_out = bool(args.output) or args.format != "text"
    USE_COLOR = not (args.no_color or os.environ.get("NO_COLOR") or quiet_out or not sys.stdout.isatty())
    args.hours_eff = args.hours if args.hours is not None else (0 if args.file else 24)
    if args.hours_eff is not None and args.hours_eff < 0:
        die("--hours must be >= 0")
    raw = DEFAULT_RULES
    if args.rules:
        custom = load_rules_file(args.rules)
        raw = custom if args.no_builtin else merge_rules(DEFAULT_RULES, custom)
    problems = []
    rules = compile_rules(raw, problems.append)
    for pr in problems:
        print(c(f"  [!] {pr}", "yellow"), file=sys.stderr)
    if not rules:
        die("no usable rules loaded")
    return rules, Allow(args.allow)


def do_scan(args, rules, allow, save_prompt=False):
    eng = run_scan(args, rules, allow)
    rep = build_report(eng)
    text = {"text": render_text, "json": render_json, "csv": render_csv, "md": render_md}[args.format](eng, rep)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"[+] Report written to {args.output}", file=sys.stderr)
        except OSError as e:
            die(f"cannot write {args.output}: {e}")
    else:
        if args.format == "text":
            print(banner())
        print(text)
    return eng, rep


def exit_code(rep):
    return 2 if rep["worst"] >= SEV_RANK["high"] else 1 if rep["worst"] >= SEV_RANK["medium"] else 0


def menu(args, rules, allow):
    last_rep = None
    while True:
        os.system("clear")
        print(banner())
        print(f"  {c('[1]', 'bold')}  Full scan ({args.hours_eff or 'all'}h window)")
        print(f"  {c('[2]', 'bold')}  Analyze a specific log file")
        print(f"  {c('[3]', 'bold')}  Disk usage + cleanup assistant")
        print(f"  {c('[4]', 'bold')}  List detection rules")
        print(f"  {c('[5]', 'bold')}  Settings (window, brute-force threshold)")
        print(f"  {c('[0]', 'bold')}  Exit\n")
        try:
            ch = input(f"  {c('>', 'cyan')} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if ch == "1":
            args.file = None
            _eng, last_rep = do_scan(args, rules, allow)
            input(c("\n  [ENTER to continue]", "yellow"))
        elif ch == "2":
            path = input(f"\n  {c('Log file path:', 'cyan')} ").strip()
            if path:
                saved = (args.file, args.hours_eff)
                args.file = [path]
                if args.hours is None:
                    args.hours_eff = 0
                _eng, last_rep = do_scan(args, rules, allow)
                args.file, args.hours_eff = saved
                input(c("\n  [ENTER to continue]", "yellow"))
        elif ch == "3":
            risk = bool(last_rep and last_rep["worst"] >= SEV_RANK["high"])
            cleanup_assistant(args, evidence_risk=risk)
            input(c("\n  [ENTER to continue]", "yellow"))
        elif ch == "4":
            list_rules(rules)
            input(c("  [ENTER to continue]", "yellow"))
        elif ch == "5":
            win = "all time" if not args.hours_eff else f"{args.hours_eff:g}h"
            print(c("\n  ── Settings ──", "bold", "cyan"))
            print(f"  Current window: {win}   Brute-force threshold: {args.threshold}")
            print(c("  (press ENTER on a prompt to keep the current value; 0 hours = all time)", "dim"))
            try:
                h = input(f"\n  Lookback hours [{win}]: ").strip()
                t = input(f"  Brute-force threshold [{args.threshold}]: ").strip()
                if h:
                    hv = float(h)
                    if hv < 0:
                        raise ValueError
                    args.hours, args.hours_eff = hv, hv
                if t:
                    tv = int(t)
                    if tv < 1:
                        raise ValueError
                    args.threshold = tv
                win = "all time" if not args.hours_eff else f"{args.hours_eff:g}h"
                print(c(f"\n  [✔] Saved: window = {win}, brute-force threshold = {args.threshold}", "green"))
            except ValueError:
                print(c("\n  [!] Invalid number, settings unchanged.", "yellow"))
            except (EOFError, KeyboardInterrupt):
                print()
            input(c("\n  [ENTER to continue]", "yellow"))
        elif ch == "0":
            return


def main():
    args = make_parser().parse_args()
    if args.dump_rules:
        dump_rules(args.dump_rules)
        return 0
    rules, allow = prepare(args)
    if args.list_rules:
        list_rules(rules)
        return 0
    if args.cleanup:
        cleanup_assistant(args)
        return 0
    interactive = (len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty() and not args.quick)
    if interactive:
        menu(args, rules, allow)
        return 0
    _eng, rep = do_scan(args, rules, allow)
    return exit_code(rep)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n  interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
