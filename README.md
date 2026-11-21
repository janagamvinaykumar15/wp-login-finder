# WordPress Login Page Finder

A Python tool to discover WordPress login pages for a given domain. It checks common WordPress login paths, tracks redirects, fingerprints login content, and can output structured JSON reports.

This project is intended for **authorized security testing and educational purposes only**.

## ⚠️ Ethical Use Disclaimer

This tool is provided for educational and authorized security auditing purposes only.

- You must have explicit written permission from the owner of any website before scanning it.
- Using this tool against systems without authorization may be illegal.
- The author assumes no responsibility for misuse or damage caused by this tool.

## Features

- Concurrent scanning with configurable thread count.
- 20 built-in WordPress login paths, including common subdirectory installs.
- Content fingerprinting using 8 detection signatures with a 2-of-8 confidence threshold.
- Redirect tracking for chains such as `/wp-admin/` → `/wp-login.php`.
- WordPress version extraction from meta generator tags and asset version strings.
- SSL fallback from HTTPS to HTTP for legacy/internal targets.
- Polite scanning options: request delay and realistic browser headers.
- JSON output for chaining into other tools.

## Key Design Features

| Feature | Implementation |
| :--- | :--- |
| Concurrent scanning | `ThreadPoolExecutor` with configurable thread count |
| 20 built-in paths | Standard + common subdirectory WordPress installs |
| Content fingerprinting | 8 detection signatures (form fields, `wp-login` strings) with 2-of-8 confidence threshold |
| Redirect tracking | Detects `/wp-admin/` → `/wp-login.php` style chains |
| WP version extraction | Meta generator + asset version regex |
| SSL fallback | Auto-fallback HTTPS → HTTP for legacy/internal targets |
| Polite scanning | `--delay` option + realistic browser headers to reduce WAF triggering |
| Structured reporting | JSON output for chaining into other tools |

## Requirements

- Python 3.8+
- `requests`
- `urllib3`

Install dependencies with pip:

```bash
pip install requests urllib3
```

## Installation

1. Download or clone this repository.
2. Install the dependencies shown above.

## Usage Examples

```bash
# Basic scan
python wpLoginFinder.py -t example.com

# With custom paths, proxy, and JSON output
python wpLoginFinder.py -t example.com -p /custom-login /wp/admin -o results.json

# Stealth mode: 1 thread, 2s delay, via Burp
python wpLoginFinder.py -t example.com -T 1 --delay 2 --proxy http://127.0.0.1:8080

# Multiple targets
for d in $(cat targets.txt); do python wpLoginFinder.py -t $d -o "reports/$d.json"; done
```

## Arguments

| Flag | Description |
| :--- | :--- |
| `-t` | Target domain to scan, e.g. `example.com` |
| `-p` | Custom login paths to check |
| `-o` | Output JSON report file |
| `-T` | Number of threads |
| `--delay` | Delay between requests in seconds |
| `--proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` |

## How It Works

The tool sends HTTP requests to a set of common WordPress login paths and analyzes responses using status codes, redirect behavior, form fields, known `wp-login` strings, and other fingerprints. A page is considered a likely login page when it matches at least 2 of the 8 configured detection signatures.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
