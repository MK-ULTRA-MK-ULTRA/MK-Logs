# MK-logs

**A Linux log analyzer that finds attacker behavior, not noise.**

MK-logs reads your system logs, spots real attack patterns (brute force, password spraying, persistence, log tampering, web scans and more), maps every finding to MITRE ATT&CK, and tells you what to look at first. It's a single Python file with no required dependencies. Drop it on a box, run it, and get a clear report.

```bash
sudo python3 mk-logs.py
```

> **MK-logs detects, it does not block.** It reads your logs and reports attacks after the fact. To automatically ban attackers, pair it with a tool like [Fail2Ban](https://github.com/fail2ban/fail2ban); MK-logs reads Fail2Ban's log too.

---

## Screenshots

<!-- 1. Take a screenshot of the tool (menu, a scan result, etc.)
     2. Save it into the screenshots/ folder, e.g. screenshots/menu.png
     3. Make sure the filename below matches. Delete these comments when done. -->

![MK-logs main menu](screenshots/menu.png)

![MK-logs scan results](screenshots/scan.png)

---

## Why MK-logs?

Most log tools flag everything: every sudo command, every firewall block, every SSH disconnect. MK-logs treats normal service behavior as normal. Rules look for attacker *behavior*, and volume-based attacks are caught by a **correlation engine** using sliding time windows, so you see "47 failed logins from one IP in 10 minutes, then a success" instead of 47 separate lines.

## Features

- **54 built-in detection rules** covering SSH attacks, new users, sudo abuse, log clearing, cron persistence, web shells, port scans, rootkit scanner hits and more
- **Correlation engine** for brute force, password spraying, port scans, web scans and success-after-failure logins
- **MITRE ATT&CK mapping** with technique IDs and names on every finding
- **Many log sources**: auth, syslog, kernel, UFW, Fail2Ban, cron, dpkg, rkhunter, chkrootkit, nginx/Apache access logs, auditd, shell history, and a `journalctl` fallback
- **Reads rotated and compressed logs** (`.1`, `.gz`, `.bz2`, `.xz`)
- **Forensics mode**: analyze a mounted disk image or backup with `--root`
- **Custom rules and allowlists** in YAML or JSON
- **Report formats**: text, JSON, CSV, Markdown
- **Cleanup assistant** for old logs, huge logs, package caches and crash dumps. It archives before emptying and warns you before destroying evidence
- **CI-friendly exit codes**: `0` clean, `1` medium, `2` high/critical

## Requirements

- Linux
- Python 3.8+
- `sudo`/root recommended (most logs in `/var/log` are root-only)
- Optional: `pip install pyyaml`, only for YAML rule files and `--dump-rules`

## Install

```bash
git clone https://github.com/MK-ULTRA-MK-ULTRA/MK-logs.git
cd MK-logs
sudo python3 mk-logs.py
```

Optional: run it from anywhere as `mk-logs`:

```bash
sudo ln -s "$PWD/mk-logs.py" /usr/local/bin/mk-logs
```

## Usage

### Interactive menu

```bash
sudo python3 mk-logs.py
```

| Option | What it does |
|-------:|--------------|
| 1 | Full scan using the current time window |
| 2 | Analyze a specific log file |
| 3 | Disk usage and cleanup assistant |
| 4 | List all detection rules |
| 5 | Settings: lookback window (hours) and brute-force threshold |
| 0 | Exit |

**Option 5 (Settings)** changes how the scanner detects things for the current session:

- **Lookback hours**: how far back the next scan reads the logs (`0` = all time).
- **Brute-force threshold**: how many failed logins from one source inside the correlation window (10 minutes by default) count as a brute-force attack. Lower is stricter, higher is quieter.

Press ENTER on a prompt to keep the current value. Settings reset when you exit; to make them permanent, use the flags `--hours` and `--threshold`.

### Command line

```bash
sudo python3 mk-logs.py --quick                    # scan everything, no menu
python3 mk-logs.py --file auth.log                 # analyze one file (all time)
sudo python3 mk-logs.py --hours 72 --rotated       # last 72h, include rotated logs
python3 mk-logs.py --format json -o report.json    # machine-readable report
python3 mk-logs.py --format md -o report.md        # Markdown report
sudo python3 mk-logs.py --cleanup --dry-run        # preview cleanup, change nothing
python3 mk-logs.py --root /mnt/evidence            # analyze a mounted disk image
python3 mk-logs.py --list-rules                    # show every detection rule
python3 mk-logs.py --dump-rules > rules.yaml       # export rules to edit
```

### Key options

| Flag | Default | Meaning |
|------|---------|---------|
| `--hours N` | 24 (all time for `--file`) | Lookback window; `0` = all time |
| `--rotated` | off | Also read rotated/compressed logs |
| `--threshold N` | 5 | Failed logins that count as brute force |
| `--window N` | 10 | Correlation window in minutes |
| `--spray-users N` | 5 | Distinct usernames = password spraying |
| `--scan-ports N` | 15 | Distinct ports = port scan |
| `--web-threshold N` | 50 | 404s in a window = web scan |
| `--min-severity` | low | Hide findings below this level |
| `--max-mb N` | 25 | Max MB read per file (from the end) |
| `--keep-days N` | 14 | Cleanup only touches items older than this |
| `--format` | text | `text`, `json`, `csv` or `md` |
| `--no-color` | off | Disable colors |

Run `python3 mk-logs.py --help` for everything.

## Custom rules

```bash
python3 mk-logs.py --dump-rules > rules.yaml
sudo python3 mk-logs.py --rules rules.yaml
```

```yaml
- id: my-rule
  name: Suspicious curl pipe to shell
  severity: high          # info | low | medium | high | critical
  category: shell
  sources: [shell]
  pattern: 'curl .*\| *(ba)?sh'
  mitre: [T1105, T1059.004]
```

## Safety

- Scanning is **read-only**; it never modifies your logs.
- Cleanup is dry-run unless you run it as root, and always dry-run with `--root`.
- Active logs are never deleted. Huge logs are gzipped to `/var/log/mk-logs-archive/` before being emptied.
- If a scan finds HIGH/CRITICAL detections, cleanup makes you type `DELETE`, because **logs are evidence**.

## Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | Nothing notable |
| 1 | Medium findings |
| 2 | High or critical findings |

## Disclaimer

For systems you own or are authorized to administer. Detections are heuristics and can produce false positives, so always verify findings.

## License

MIT, see `LICENSE`.

---

*Part of the MK-ULTRA toolkit.*
