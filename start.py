#!/usr/bin/env python3
"""WordpresVuln - Basic WordPress security recon scanner.

Only run this against sites you own or are explicitly authorized to test.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

USER_AGENT = "WordpresVuln/1.1 (+https://github.com/devlewiso/WordpresVuln)"
TIMEOUT = 10

SENSITIVE_URLS = [
    "wp-admin/",
    "wp-login.php",
    "wp-config.php",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-content/uploads/",
    "xmlrpc.php",
    "wp-json/wp/v2/users",
    "readme.html",
]

# Known-vulnerable plugin/theme slugs to probe for (presence != confirmed exploit;
# always cross-check the reported version against a CVE database before acting).
VULNERABLE_PLUGINS = [
    "revslider",
    "contact-form-7",
    "wp-file-manager",
    "elementor",
    "duplicator",
    "wpforms-lite",
    "wordfence",
    "advanced-custom-fields",
]


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def get_baseline_signature(session: requests.Session, base_url: str, verify_ssl: bool):
    """Fetch a clearly-nonexistent path to detect soft-404s (sites that return
    HTTP 200 for everything), which would otherwise cause false positives."""
    probe = urljoin(base_url, f"this-path-should-not-exist-{int(datetime.now().timestamp())}/")
    try:
        resp = session.get(probe, timeout=TIMEOUT, verify=verify_ssl, allow_redirects=True)
        return resp.status_code, len(resp.content)
    except requests.RequestException:
        return None, None


def is_real_hit(resp, baseline_status, baseline_len) -> bool:
    if resp.status_code != 200:
        return False
    if baseline_status == 200 and abs(len(resp.content) - (baseline_len or 0)) < 25:
        return False  # looks like the same soft-404 page
    return True


def check_sensitive_urls(session, base_url, verify_ssl, baseline):
    print("Checking for sensitive URLs...")
    baseline_status, baseline_len = baseline
    results = []
    for path in SENSITIVE_URLS:
        full_url = urljoin(base_url, path)
        try:
            resp = session.get(full_url, timeout=TIMEOUT, verify=verify_ssl, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[!] Error checking {full_url}: {exc}")
            continue
        hit = is_real_hit(resp, baseline_status, baseline_len)
        status = "Accessible" if hit else "Not accessible"
        marker = "+" if hit else "-"
        print(f"[{marker}] {status}: {full_url} ({resp.status_code})")
        results.append({"url": full_url, "status_code": resp.status_code, "accessible": hit})
    return results


def check_vulnerable_plugins(session, base_url, verify_ssl, baseline):
    print("\nChecking for known plugin/theme slugs...")
    baseline_status, baseline_len = baseline
    results = []
    for plugin in VULNERABLE_PLUGINS:
        full_url = urljoin(base_url, f"wp-content/plugins/{plugin}/")
        try:
            resp = session.get(full_url, timeout=TIMEOUT, verify=verify_ssl, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[!] Error checking {plugin}: {exc}")
            continue
        found = is_real_hit(resp, baseline_status, baseline_len)
        version = None
        if found:
            version = fetch_plugin_version(session, base_url, plugin, verify_ssl)
            label = f"{plugin}" + (f" (version {version})" if version else "")
            print(f"[+] Found: {label} at {full_url}")
        else:
            print(f"[-] Not found: {plugin}")
        results.append({"plugin": plugin, "url": full_url, "found": found, "version": version})
    return results


def fetch_plugin_version(session, base_url, plugin, verify_ssl):
    readme_url = urljoin(base_url, f"wp-content/plugins/{plugin}/readme.txt")
    try:
        resp = session.get(readme_url, timeout=TIMEOUT, verify=verify_ssl)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    match = re.search(r"Stable tag:\s*([\w.\-]+)", resp.text, re.IGNORECASE)
    return match.group(1) if match else None


def main():
    parser = argparse.ArgumentParser(
        description="Basic WordPress recon scanner: checks for exposed sensitive "
        "paths and the presence of commonly-vulnerable plugins/themes. "
        "Use only on sites you own or are authorized to test."
    )
    parser.add_argument("url", nargs="?", help="Target site, e.g. https://example.com")
    parser.add_argument("-o", "--output", help="Write a JSON report to this path")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    args = parser.parse_args()

    base_url = args.url or input("Enter the WordPress site URL (e.g., http://example.com): ").strip()
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    if not base_url.endswith("/"):
        base_url += "/"

    verify_ssl = not args.insecure
    session = make_session()
    baseline = get_baseline_signature(session, base_url, verify_ssl)

    urls_report = check_sensitive_urls(session, base_url, verify_ssl, baseline)
    plugins_report = check_vulnerable_plugins(session, base_url, verify_ssl, baseline)
    print("\nScan complete.")

    if args.output:
        report = {
            "target": base_url,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "sensitive_urls": urls_report,
            "plugins": plugins_report,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
