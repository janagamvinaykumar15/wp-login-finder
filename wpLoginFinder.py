#!/usr/bin/env python3
"""
wpLoginFinder.py - Advanced WordPress Login Page Discovery Tool
Author: Senior Security Engineering Team
Description: Enumerates WordPress login endpoints on target domains using
             concurrent HTTP requests, path discovery, and content-based
             detection heuristics.
Usage: python wpLoginFinder.py -t target.com [options]
"""

import argparse
import concurrent.futures
import logging
import random
import re
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3

# Suppress insecure TLS warnings (self-signed certs common in testing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "2.4.1"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Candidate login paths (ordered by likelihood)
LOGIN_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/login",
    "/admin",
    "/wp-login.php?redirect_to=%2Fwp-admin%2F",
    "/wordpress/wp-login.php",
    "/blog/wp-login.php",
    "/cms/wp-login.php",
    "/site/wp-login.php",
    "/wp/wp-login.php",
    "/new/wp-login.php",
    "/old/wp-login.php",
    "/test/wp-login.php",
    "/dev/wp-login.php",
    "/staging/wp-login.php",
    "/backup/wp-login.php",
    "/main/wp-login.php",
    "/portal/wp-login.php",
    "/secure/wp-login.php",
    "/auth/wp-login.php",
]

# Common login page content fingerprints
WP_LOGIN_FINGERPRINTS = [
    "wp-login.php",
    "user_login",
    "user_pass",
    "rememberme",
    "Lost your password?",
    "Password Reset",
    "action=lostpassword",
    "wp-submit",
]

# HTTP probe methods for info gathering
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
FOUND_STATUSES = {200}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class ColoredFormatter(logging.Formatter):
    """Adds terminal colors to log output."""
    COLORS = {
        "DEBUG": "\033[94m",
        "INFO": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "CRITICAL": "\033[1;91m",
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.msg = f"{color}{record.msg}{self.RESET}"
        return super().format(record)


def setup_logging(verbose: bool) -> logging.Logger:
    """Configure logging with colored output."""
    logger = logging.getLogger("wpLoginFinder")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter("[%(levelname)s] %(asctime)s - %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    return logger


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class LoginEndpoint:
    """Represents a discovered WordPress login endpoint."""
    url: str
    status_code: int
    fingerprints: list = field(default_factory=list)
    redirected_to: str = ""
    response_time: float = 0.0
    is_wp_login: bool = False

    def __str__(self):
        return f"{self.url} [{self.status_code}]" + (f" -> {self.redirected_to}" if self.redirected_to else "")


@dataclass
class ScanResult:
    """Aggregated scan results for a target."""
    target: str
    endpoints: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    total_time: float = 0.0
    wp_version: str = ""
    generator_meta: str = ""

    @property
    def confirmed_logins(self):
        return [e for e in self.endpoints if e.is_wp_login]


# ---------------------------------------------------------------------------
# Core Scanner
# ---------------------------------------------------------------------------


class WordPressLoginFinder:
    """Scans a WordPress domain for login endpoints using concurrent probes."""

    def __init__(
        self,
        target: str,
        timeout: int = 10,
        max_workers: int = 15,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        delay: float = 0.0,
        proxy: str = None,
        custom_paths: list = None,
        detect_redirects: bool = True,
    ):
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.delay = delay
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.custom_paths = custom_paths or []
        self.detect_redirects = detect_redirects
        self.logger = logging.getLogger("wpLoginFinder")
        self.session = self._create_session()

    # -- Setup helpers -----------------------------------------------------

    @staticmethod
    def _normalize_target(target: str) -> str:
        """Ensure target has scheme and no trailing slash."""
        if not urlparse(target).scheme:
            target = f"https://{target}"
        # Try http if https fails later
        return target.rstrip("/")

    def _create_session(self) -> requests.Session:
        """Create a session with realistic headers."""
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Cache-Control": "max-age=0",
            }
        )
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = self.proxy
        return session

    # -- Detection methods -------------------------------------------------

    def _check_wp_fingerprints(self, content: str) -> list:
        """Check for WordPress login fingerprints in HTML content."""
        return [fp for fp in WP_LOGIN_FINGERPRINTS if fp.lower() in content.lower()]

    def _extract_wp_version(self, content: str) -> str:
        """Extract WordPress version from meta generator or version strings."""
        patterns = [
            r'<meta\s+name="generator"\s+content="WordPress\s+([\d.]+)"',
            r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)",
            r"\?ver=([\d.]+).*?wp-content",
        ]
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    def _check_ssl_fallback(self) -> str:
        """Try HTTP if HTTPS fails (internal/legacy environments)."""
        if self.target.startswith("https://"):
            http_url = self.target.replace("https://", "http://")
            try:
                requests.head(http_url, timeout=self.timeout, verify=False)
                self.logger.debug(f"HTTPS failed, falling back to HTTP: {http_url}")
                return http_url
            except requests.RequestException:
                pass
        return self.target

    def _probe_endpoint(self, url: str) -> LoginEndpoint:
        """Probe a single URL for WordPress login characteristics."""
        endpoint = LoginEndpoint(url=url, status_code=0)
        start = time.time()
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                proxies=self.proxy,
            )
            endpoint.response_time = round(time.time() - start, 3)
            endpoint.status_code = response.status_code

            # Track final URL after redirects
            if response.url != url:
                endpoint.redirected_to = str(response.url)

            if response.status_code in FOUND_STATUSES:
                content = response.text
                fingerprints = self._check_wp_fingerprints(content)
                endpoint.fingerprints = fingerprints
                # Confidence: require >=2 fingerprints
                endpoint.is_wp_login = len(fingerprints) >= 2
                if not self.result.wp_version:
                    self.result.wp_version = self._extract_wp_version(content)
        except requests.exceptions.SSLError as e:
            self.logger.debug(f"SSL error on {url}: {e}")
            self.result.errors.append(f"SSL: {url}")
        except requests.exceptions.ConnectionError as e:
            self.logger.debug(f"Connection error on {url}: {e}")
            self.result.errors.append(f"Connection: {url}")
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout on {url}")
            self.result.errors.append(f"Timeout: {url}")
        except requests.RequestException as e:
            self.logger.debug(f"Request failed on {url}: {e}")
            self.result.errors.append(f"Error: {url}")
        return endpoint

    # -- Main scanning -----------------------------------------------------

    def scan(self) -> ScanResult:
        """Execute the full login-page discovery scan."""
        self.result = ScanResult(target=self.target)
        start_time = time.time()

        self.logger.info(f"Starting scan on: {self.target}")

        # Verify target is reachable and check HTTP fallback
        if not self._check_target_reachable():
            self.logger.error("Target unreachable, aborting scan.")
            return self.result

        # Build path list
        paths = LOGIN_PATHS + self.custom_paths
        self.logger.info(f"Probing {len(paths)} candidate paths with {self.max_workers} threads")

        # Concurrent probe
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self._probe_endpoint, urljoin(self.target, p)): p for p in paths
            }
            for future in concurrent.futures.as_completed(future_to_url):
                endpoint = future.result()
                self.result.endpoints.append(endpoint)
                if endpoint.is_wp_login:
                    self.logger.success(f"FOUND: {endpoint}")
                elif endpoint.status_code == 200:
                    self.logger.debug(f"200 OK (not WP login): {endpoint.url}")

                # Respect per-request delay if configured
                if self.delay:
                    time.sleep(self.delay)

        self.result.total_time = round(time.time() - start_time, 2)
        self.logger.info(f"Scan complete in {self.result.total_time}s")
        return self.result

    def _check_target_reachable(self) -> bool:
        """Check if the target responds before running the full scan."""
        try:
            r = self.session.get(self.target, timeout=self.timeout, allow_redirects=True)
            self.logger.debug(f"Target reachable: {self.target} [{r.status_code}]")
            if r.status_code == 404:
                self.logger.warning("Target returned 404 on root; paths may still be valid.")
            return True
        except requests.exceptions.SSLError:
            # Try HTTP fallback
            fallback = self._check_ssl_fallback()
            if fallback != self.target:
                self.target = fallback
                return True
            return False
        except requests.RequestException:
            return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Formats scan results for console and file output."""

    @staticmethod
    def console_report(result: ScanResult, logger: logging.Logger):
        """Print a formatted summary to the console."""
        logger.info("=" * 60)
        logger.info("Scan Summary")
        logger.info("=" * 60)
        logger.info(f"Target:         {result.target}")
        logger.info(f"Duration:       {result.total_time}s")
        logger.info(f"WP Version:     {result.wp_version or 'Not detected'}")
        logger.info(f"Total Probed:   {len(result.endpoints)}")
        logger.info(f"Errors:         {len(result.errors)}")
        confirmed = result.confirmed_logins
        logger.info(f"Confirmed:      {len(confirmed)}")
        if confirmed:
            logger.info("-" * 60)
            for ep in confirmed:
                logger.info(f"  [+] {ep}")
                if ep.fingerprints:
                    logger.info(f"      Fingerprints: {', '.join(ep.fingerprints[:3])}")

    @staticmethod
    def save_report(result: ScanResult, output_path: Path):
        """Save results as JSON report."""
        import json
        data = {
            "target": result.target,
            "scan_time": result.total_time,
            "wp_version": result.wp_version,
            "confirmed_logins": [
                {
                    "url": e.url,
                    "status": e.status_code,
                    "redirected_to": e.redirected_to,
                    "fingerprints": e.fingerprints,
                    "response_time": e.response_time,
                }
                for e in result.confirmed_logins
            ],
            "all_probes": [
                {"url": e.url, "status": e.status_code} for e in result.endpoints
            ],
        }
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"WordPress Login Page Finder v{VERSION}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", type=Path, help="Output JSON report file")
    parser.add_argument("-T", "--threads", type=int, default=15, help="Max concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose debug output")
    parser.add_argument("-p", "--paths", nargs="+", help="Additional custom paths to probe")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    logger = setup_logging(args.verbose)
    # Patch logger.success since standard logging lacks it
    logger.success = lambda msg, *a, **kw: logger.info(msg, *a, **kw)

    banner = f"""
    ╔══════════════════════════════════════════╗
    ║   WordPress Login Finder v{VERSION:<14}   ║
    ╚══════════════════════════════════════════╝
    """
    print(banner)

    try:
        finder = WordPressLoginFinder(
            target=args.target,
            timeout=args.timeout,
            max_workers=args.threads,
            verify_ssl=args.verify_ssl,
            delay=args.delay,
            proxy=args.proxy,
            custom_paths=args.paths or [],
        )
        result = finder.scan()
        ReportGenerator.console_report(result, logger)

        if args.output:
            ReportGenerator.save_report(result, args.output)
            logger.info(f"Report saved: {args.output}")

        return 0 if result.confirmed_logins else 1
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        return 130
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}")
        if args.verbose:
            raise
        return 2


if __name__ == "__main__":
    sys.exit(main())
