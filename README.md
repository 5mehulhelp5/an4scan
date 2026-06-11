# AN4SCAN — CMS Malware & Vulnerability Scanner

Single-binary security scanner for **Magento 1 & 2**, **WordPress**, and **PrestaShop**. Auto-detects the CMS, then runs targeted checks: backdoors, skimmers, obfuscated code, plugin vulnerabilities, core file integrity, database injections, known CVEs, malicious processes, and exploit attempts in access logs.

No dependencies. Just download and run. All scan modules enabled by default.

## Install

### One-liner (Linux x86_64)

```bash
curl -sL https://github.com/mabt/an4scan/releases/latest/download/an4scan-linux-amd64 -o /usr/local/bin/an4scan && chmod +x /usr/local/bin/an4scan
```

### Other platforms

| Platform | Command |
|----------|---------|
| Linux x86_64 | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-linux-amd64 && chmod +x /usr/local/bin/an4scan` |
| Linux ARM64 | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-linux-arm64 && chmod +x /usr/local/bin/an4scan` |
| macOS Intel | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-darwin-amd64 && chmod +x /usr/local/bin/an4scan` |
| macOS ARM (M1+) | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-darwin-arm64 && chmod +x /usr/local/bin/an4scan` |

### Build from source

```bash
git clone https://github.com/mabt/an4scan.git
cd an4scan && go build -o an4scan .
```

## Quick Start

```bash
# Scan a site (auto-detects CMS, all modules enabled)
an4scan /var/www/html

# Deep mode (include suspicions)
an4scan /var/www/html --deep

# HTML report
an4scan /var/www/html --html report.html

# Summary only
an4scan /var/www/html -q
```

## Features

| Module | Flag | Default | What it does |
|--------|------|---------|--------------|
| **File scan** | *(always on)* | on | 120+ regex signatures: backdoors, skimmers, webshells, obfuscation, CMS-specific patterns |
| **CMS detection** | *(automatic)* | on | Auto-detect Magento 1/2, WordPress, PrestaShop — loads CMS-specific signatures |
| **Version + CVEs** | `--version` | on | Detect version, check against 60+ known CVEs |
| **Plugin scan** | `--plugins` | on | List plugins/modules, check against known vulnerable versions |
| **Core integrity** | `--integrity` | on | WordPress: verify checksums via wordpress.org API. Magento/PS: mtime-based |
| **Database scan** | `--db` | on | Scan CMS tables for injected scripts, suspicious admins, cron jobs |
| **Log analysis** | `--logs` | on | Parse Apache/Nginx logs for exploit attempts, brute force, SQLi |
| **Permissions** | `--permissions` | on | World-writable files, SUID/SGID, readable credentials |
| **Modified files** | `--mtime` | on | Core files modified recently (default: 7 days) |
| **YARA scan** | `--yara` | on | 4 built-in rules + community rulesets (auto-downloaded) |
| **Process scan** | `--processes` | on | Detect reverse shells, crypto miners, rootkits, C2 connections |
| **Timeline** | *(automatic)* | on | Reconstructs infection timeline from findings |
| **Deep mode** | `--deep` | off | Include MEDIUM/LOW/INFO findings |

All modules are enabled by default. Use `--no-<module>=false` to disable specific ones (e.g. `--db=false`).

## Detection Sources

an4scan combines multiple detection engines in a single binary:

### Built-in signatures (120+)
- Credit card skimmers / Magecart patterns
- PHP backdoors & webshells (eval, assert, preg_replace /e, create_function, etc.)
- Obfuscation (base64 chains, gzinflate, hex encoding, chr() concatenation, zero-width Unicode evasion)
- Suspicious file operations (droppers, remote file inclusion)
- CMS-specific: Magento (40+), WordPress (35+), PrestaShop (35+)
- Multi-line detection (5-line sliding window for split eval/decode chains)

### YARA rules (auto-updated)
Community rulesets are automatically downloaded before scanning (cached 24h):

| Ruleset | Source | Description |
|---------|--------|-------------|
| **sansec-magento** | [gwillem/magento-malware-scanner](https://github.com/gwillem/magento-malware-scanner) | Largest public Magento malware signature collection (Sansec/ecomscan) |
| **signature-base** | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | 4000+ rules: webshells, exploits, APT tools (Florian Roth) |
| **reversinglabs** | [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | Malware family detection rules |
| **elastic** | [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) | Cross-platform malware YARA (Linux, Windows, macOS) |
| **magesec** | [magesec/magesecurityscanner](https://github.com/magesec/magesecurityscanner) | Mage Security Council rules |

Requires `yara` binary in PATH. Rules are stored in `~/.an4scan/rules/` and refreshed every 24h automatically. Use `--no-update` to skip, or `--update` to force a refresh.

### Database signatures (10 patterns)
Scans CMS tables (`core_config_data`, `cms_block`, `cms_page`, `email_template`, `newsletter_template`, `catalog_*_text`, `translation`) for injected JavaScript, PHP, and obfuscated payloads. Also checks for suspicious admin users and cron jobs.

### Process scanner (13 patterns + network)
Reads `/proc` to detect:
- Reverse shells (pty.spawn, bash /dev/tcp, netcat, socat, python socket, perl)
- Fake kernel threads (rootkit-style process hiding)
- Crypto miners (xmrig, stratum+tcp)
- PHP backdoors running from /tmp
- LD_PRELOAD hijacking
- Suspicious outbound connections on known C2 ports (4444, 5555, 31337, etc.)

### CVE databases
Hardcoded CVE lists for Magento (2.3.x–2.4.7), WordPress, and PrestaShop with CVSS scores.

### Log exploit patterns (12 patterns)
Detects exploit attempts in Apache/Nginx access logs: path traversal, PHP injection, webshell access, brute force, xmlrpc abuse.

### Plugin vulnerability database
Known vulnerable versions for Magento extensions, WordPress plugins/themes, and PrestaShop modules.

## Output Modes

| Flag | Description |
|------|-------------|
| `--html report.html` | Standalone HTML report (dark theme, no external deps) |
| `-j` / `--json` | JSON output |
| `-q` / `--quiet` | One-line summary |
| `-o` / `--output FILE` | Save text report to file |
| `--save` | Save scan results for future diffing |
| `--diff auto` | Compare with last saved scan (show new/resolved findings) |

## Usage Examples

### Standard scan

```bash
an4scan /var/www/html
```

All modules run by default. Only CRITICAL/HIGH findings shown.

### Deep scan (include suspicions)

```bash
an4scan /var/www/html --deep
```

Also reports MEDIUM/LOW/INFO: obfuscation, unusual files, low-confidence matches.

### Plugin vulnerability check

```bash
an4scan /var/www/html
```

Detects installed plugins/modules, checks versions against known CVEs. Supports:
- **Magento 1**: reads `app/etc/modules/*.xml` + `app/code/community/`
- **Magento 2**: extensions from `composer.lock` + `app/code/`
- **WordPress**: plugins, themes, mu-plugins (reads PHP headers)
- **PrestaShop**: modules (reads `$this->version`)

### Core file integrity

```bash
an4scan /var/www/html
```

- **WordPress**: fetches official checksums from `api.wordpress.org`, verifies every core file MD5. Detects unknown PHP files in `wp-admin/` and `wp-includes/`.
- **Magento/PrestaShop**: detects core files modified after last install.

### HTML report

```bash
an4scan /var/www/html --html report.html
```

Produces a standalone HTML file with dark theme. Includes all findings, CVEs, plugin vulnerabilities, integrity results, timeline, and suspicious IPs.

### Diff between scans

```bash
# First scan — save results
an4scan /var/www/html --save

# Later — compare with last saved scan
an4scan /var/www/html --diff auto
```

Shows new findings and resolved findings since the last scan.

### Other examples

```bash
# JSON export for CI/CD
an4scan /var/www/html -j > report.json

# Custom log path
an4scan /var/www/html --log-path /var/log/nginx/access.log

# YARA scan with custom rules
an4scan /var/www/html --yara-rules /path/to/rules/

# Exclude paths (known false positives)
an4scan /var/www/html --whitelist vendor/custom,app/code/MyModule

# Skip YARA auto-update (offline mode)
an4scan /var/www/html --no-update

# Force update YARA rulesets
an4scan --update

# Show installed rulesets
an4scan --status

# Scan deployer/capistrano symlink structure
an4scan /var/www/current
```

## CMS-Specific Detection

### Magento 1

- Backdoor/webshell signatures adapted for M1 directory structure
- Version detection from `app/Mage.php` (Community/Enterprise)
- Database config from `app/etc/local.xml` (CDATA + plain XML)
- EOL warning (M1 reached EOL June 2020)
- Whitelisted core paths: `lib/Zend/`, `lib/Varien/`, `app/code/core/Mage/`

### Magento 2

- 40+ file signatures (skimmers, backdoor patterns, core tampering)
- 27 known CVEs (CosmicSting, template injection, command injection...)
- Extension vulnerability database
- DB scan: `core_config_data`, `cms_block`, `cms_page`, `email_template`, admin users, cron
- Symlink traversal for deployer/capistrano setups (`current -> releases/xxx`)

### WordPress

- 12 WP-specific signatures (WooCommerce skimmers, plugin backdoors, SEO spam, xmlrpc abuse)
- 14 core CVEs + 25 plugin CVEs (Elementor, LiteSpeed Cache, Wordfence, WooCommerce, Contact Form 7...)
- Core integrity via official wordpress.org checksums API
- 7 WP-specific log patterns (wp-login brute force, xmlrpc, REST API enumeration)

### PrestaShop

- 11 PS-specific signatures (module backdoors, Smarty template injection, payment hooks)
- 16 core CVEs + 10 module CVEs (SQL Manager RCE, pk_faq, blockwishlist...)
- 5 PS-specific log patterns (admin brute force, module exploits, SQL Manager)

## Options Reference

```
  path                    CMS root path (auto-detects Magento 1/2, WordPress, PrestaShop)

scan modules (all enabled by default):
  --deep                  Include suspicions (default: confirmed threats only)
  --db                    Scan database for injected malware (default: true)
  --version               Detect version and check known CVEs (default: true)
  --plugins               Scan plugins/modules for known vulnerabilities (default: true)
  --integrity             Check core file integrity (default: true)
  --mtime                 Recently modified core files (default: true)
  --mtime-days N          Time window for --mtime (default: 7)
  --permissions           Check file permissions (default: true)
  --logs                  Analyze access logs (default: true)
  --log-path PATH         Access log file path(s), comma-separated
  --yara                  YARA scanning (default: true)
  --yara-rules PATH       Additional YARA rules file or directory
  --processes             Scan running processes (default: true)

output:
  -j, --json              JSON output
  --html FILE             Write HTML report
  -o, --output FILE       Save text report to file
  -q, --quiet             One-line summary only
  -s, --severity LEVEL    Override severity filter (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  -v, --verbose           Show scan errors

diff:
  --save                  Save scan for future diffing (in .an4scan/)
  --diff PATH             Compare with previous scan JSON ("auto" for last saved)

tuning:
  -w, --workers N         Parallel workers (default: 4)
  --whitelist PATHS       Comma-separated paths to exclude from scan
  --no-update             Skip automatic YARA ruleset update

ruleset management:
  --update                Download/update community YARA rulesets
  --status                Show installed YARA rulesets
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one HIGH finding |
| `2` | At least one CRITICAL finding |

```bash
an4scan /var/www/html -q
if [ $? -eq 2 ]; then
  echo "CRITICAL: malware detected!"
fi
```

## License

MIT
