# Reference: vuln_scan.py

A dependency-free (Python 3.8+ standard library) scanner with two modes.

## CLI

```bash
# Website checks (passive)
python scripts/vuln_scan.py web <url-or-host>
python scripts/vuln_scan.py web <url-or-host> --probe      # + active sensitive-path probing
python scripts/vuln_scan.py web <url-or-host> --json

# Software dependency checks (OSV.dev)
python scripts/vuln_scan.py deps <path-to-manifest>
python scripts/vuln_scan.py deps <path> --json
```

Exit code is `1` when any actionable (non-INFO) finding exists, else `0` — suitable as a CI gate.

## Web mode checks

| Area | What is inspected |
|------|-------------------|
| Security headers | `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` |
| TLS | scheme (HTTP vs HTTPS), certificate validity/expiry, negotiated protocol version |
| Cookies | `Secure`, `HttpOnly`, `SameSite` attributes on every `Set-Cookie` |
| Disclosure | `Server`, `X-Powered-By`, `X-AspNet(Mvc)-Version` banners |
| `--probe` | HTTP 200 responses for `/.git/config`, `/.env`, `/.aws/credentials`, `/server-status`, `/phpinfo.php`, `/.svn/entries`, `/backup.zip`, `/wp-config.php.bak` |

## Deps mode

Supported manifests and the OSV ecosystem they map to:

| File | Ecosystem | Notes |
|------|-----------|-------|
| `requirements.txt` | PyPI | only exact `name==version` pins are checked |
| `package-lock.json` | npm | lockfile v1, v2, and v3 |
| `go.mod` | Go | `require` blocks and single-line requires |
| `Gemfile.lock` | RubyGems | `specs:` section |
| `poetry.lock` | PyPI | `[[package]]` entries |

Versions are sent to the OSV batch endpoint `POST https://api.osv.dev/v1/querybatch`. Each
package with one or more advisories is reported with its OSV IDs and a remediation link
(`https://osv.dev/vulnerability/<id>`). No API key is required.

## Key functions

| Function | Purpose |
|----------|---------|
| `check_security_headers(url)` | Fetch the URL and evaluate response headers + cookies |
| `check_tls(url)` | TLS handshake; report protocol and certificate expiry/validity |
| `probe_sensitive_paths(base_url)` | Active check for commonly-exposed files (gated by `--probe`) |
| `detect_and_parse(path)` | Select a parser by filename and extract `(ecosystem, name, version)` tuples |
| `query_osv(packages)` | Batch-query OSV.dev and return packages with known advisories |
| `print_report(target, findings)` | Severity-sorted human-readable report; returns actionable count |

## Notes & limitations

- Passive web checks reflect only what a single normal request reveals; they are not a substitute
  for a full web-application penetration test.
- Dependency mode requires **pinned/locked** versions; unpinned ranges (e.g. `flask>=1.0`) are skipped
  because a known-vulnerability lookup needs an exact version.
- OSV coverage depends on the ecosystem; absence of a finding is not proof a package is safe.
- Network egress to the target and to `api.osv.dev` is required; in restricted environments the
  scanner degrades gracefully and reports an INFO note instead of failing.
