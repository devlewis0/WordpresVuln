# WordpresVuln

A lightweight command-line recon scanner for WordPress sites. It checks for
commonly-exposed sensitive paths (`wp-admin`, `wp-config.php`, `xmlrpc.php`,
the REST API user endpoint, etc.) and probes for the presence of a list of
plugins/themes that have historically shipped serious vulnerabilities.

Built to do quick, authorized security checkups on small WordPress sites
(originally for a friend's small business site).

> ⚠️ **Only run this against sites you own or have explicit permission to
> test.** Scanning third-party sites without authorization is illegal in most
> jurisdictions.

## What it does

- **Sensitive URL check** — requests a set of paths that shouldn't normally
  be exposed and reports which ones respond.
- **Plugin/theme probe** — checks whether a curated list of plugin slugs
  (e.g. `revslider`, `contact-form-7`, `elementor`, `wordfence`) are
  installed, and tries to read the installed version from each plugin's
  `readme.txt`.
- **Soft-404 detection** — many sites return HTTP 200 for every path (custom
  error pages, SPA fallbacks). The scanner first requests a random
  nonexistent path as a baseline and compares response size against it, so
  those sites don't produce a wall of false positives.
- **JSON report export** — optionally write the full result set to a file
  for later reference.

Finding a plugin installed is **not** a confirmed vulnerability — always
cross-check the reported version against a CVE/vulnerability database (e.g.
WPScan's vulnerability feed) before drawing conclusions.

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

```bash
python start.py https://example.com
python start.py https://example.com -o report.json
python start.py https://example.com --insecure   # skip TLS verification
```

Or run it without arguments to be prompted for the URL interactively.

## License

MIT — see [LICENSE](LICENSE).
