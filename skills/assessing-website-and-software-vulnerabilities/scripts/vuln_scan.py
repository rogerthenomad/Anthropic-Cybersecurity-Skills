#!/usr/bin/env python3
"""Website and software vulnerability scanner.

Two scan modes, both dependency-free (Python 3.8+ standard library only):

  web   Passive/light checks against an authorized web target: HTTP security
        headers, TLS certificate and protocol, and cookie attributes. An
        optional --probe pass checks a short list of commonly-exposed sensitive
        paths and is OFF by default.

  deps  Software composition analysis: parse a dependency manifest or lockfile,
        resolve exact package versions, and query the free OSV.dev database
        (https://osv.dev) for known vulnerabilities. No API key required.

AUTHORIZATION: Only scan systems you own or are explicitly authorized to test.
The --probe option sends requests for specific paths and must be enabled
deliberately with acknowledgement of authorization.
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

USER_AGENT = "vuln-scan/1.0 (+authorized-security-assessment)"
TIMEOUT = 20

# Severity ordering for sorting/printing.
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def finding(severity, title, detail, recommendation=""):
    return {
        "severity": severity.upper(),
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }


# --------------------------------------------------------------------------- #
# Web checks
# --------------------------------------------------------------------------- #

# Recommended response headers -> (severity if missing, guidance).
SECURITY_HEADERS = {
    "strict-transport-security": ("HIGH", "Enforce HTTPS with HSTS, e.g. 'max-age=31536000; includeSubDomains'."),
    "content-security-policy": ("HIGH", "Define a CSP to mitigate XSS and data injection."),
    "x-content-type-options": ("MEDIUM", "Set 'nosniff' to stop MIME-type sniffing."),
    "x-frame-options": ("MEDIUM", "Set 'DENY' or 'SAMEORIGIN' (or use CSP frame-ancestors) to prevent clickjacking."),
    "referrer-policy": ("LOW", "Set a privacy-preserving value such as 'strict-origin-when-cross-origin'."),
    "permissions-policy": ("LOW", "Restrict powerful browser features you do not use."),
}

# Headers that leak stack/version information.
DISCLOSURE_HEADERS = {
    "server": "Reveals server software/version; trim to a generic value.",
    "x-powered-by": "Reveals framework/runtime; remove this header.",
    "x-aspnet-version": "Reveals ASP.NET version; remove this header.",
    "x-aspnetmvc-version": "Reveals ASP.NET MVC version; remove this header.",
}

# A short, conservative list of commonly-exposed sensitive paths (--probe only).
SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/.aws/credentials",
    "/server-status",
    "/phpinfo.php",
    "/.svn/entries",
    "/backup.zip",
    "/wp-config.php.bak",
]


def _http_request(url, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    # We intentionally still connect to report on otherwise-invalid certs.
    return urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)


def check_security_headers(url):
    findings = []
    try:
        resp = _http_request(url)
    except urllib.error.HTTPError as exc:
        # An error status still carries headers worth analysing.
        resp = exc
    except (urllib.error.URLError, ssl.SSLError, socket.error) as exc:
        return [finding("INFO", "Target unreachable", f"Could not fetch {url}: {exc}")], None

    headers = {k.lower(): v for k, v in resp.headers.items()}
    status = getattr(resp, "status", getattr(resp, "code", "?"))

    for name, (sev, guidance) in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append(finding(sev, f"Missing header: {name}", f"Response from {url} (HTTP {status}) omits '{name}'.", guidance))

    for name, guidance in DISCLOSURE_HEADERS.items():
        if name in headers and headers[name].strip():
            findings.append(finding("LOW", f"Information disclosure: {name}", f"'{name}: {headers[name]}'", guidance))

    # Cookie attribute analysis.
    for raw in resp.headers.get_all("Set-Cookie") or []:
        cookie_name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = [a for a in ("secure", "httponly") if a not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            findings.append(finding(
                "MEDIUM", f"Weak cookie flags: {cookie_name}",
                f"Cookie '{cookie_name}' is missing: {', '.join(missing)}.",
                "Set Secure, HttpOnly, and an explicit SameSite attribute on session cookies."))
    return findings, headers


def check_tls(url):
    findings = []
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        findings.append(finding("HIGH", "No transport encryption", f"{url} is served over HTTP.",
                                "Serve the site exclusively over HTTPS and redirect HTTP to HTTPS."))
        return findings
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                proto = tls.version()
    except ssl.SSLCertVerificationError as exc:
        findings.append(finding("HIGH", "Invalid TLS certificate", f"Certificate verification failed for {host}: {exc.verify_message if hasattr(exc, 'verify_message') else exc}.",
                                "Install a valid certificate from a trusted CA covering this hostname."))
        return findings
    except (ssl.SSLError, socket.error) as exc:
        findings.append(finding("MEDIUM", "TLS handshake failed", f"Could not complete TLS handshake with {host}:{port}: {exc}."))
        return findings

    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(finding("HIGH", "Outdated TLS protocol", f"Server negotiated {proto}.",
                                "Disable TLS 1.1 and below; require TLS 1.2+ (prefer TLS 1.3)."))

    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(finding("CRITICAL", "Expired TLS certificate", f"Certificate expired {abs(days_left)} day(s) ago ({not_after}).",
                                    "Renew the certificate immediately."))
        elif days_left < 21:
            findings.append(finding("MEDIUM", "TLS certificate expiring soon", f"Certificate expires in {days_left} day(s) ({not_after}).",
                                    "Renew before expiry and automate renewal."))
    if not findings:
        findings.append(finding("INFO", "TLS looks healthy", f"{host} negotiated {proto} with a valid certificate."))
    return findings


def probe_sensitive_paths(base_url):
    findings = []
    base = base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        target = base + path
        try:
            resp = _http_request(target)
            status = getattr(resp, "status", 200)
            body_sample = resp.read(256)
            if status == 200 and body_sample:
                findings.append(finding("HIGH", "Exposed sensitive path", f"{target} returned HTTP 200.",
                                        "Remove or block public access to this resource."))
        except urllib.error.HTTPError:
            continue  # 403/404 etc. is the expected, safe result.
        except (urllib.error.URLError, ssl.SSLError, socket.error):
            continue
    if not findings:
        findings.append(finding("INFO", "No common sensitive paths exposed", f"Checked {len(SENSITIVE_PATHS)} known paths on {base}."))
    return findings


def scan_web(url, probe=False):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    findings = []
    header_findings, _ = check_security_headers(url)
    findings += header_findings
    findings += check_tls(url)
    if probe:
        findings += probe_sensitive_paths(url)
    return findings


# --------------------------------------------------------------------------- #
# Dependency (software) checks via OSV.dev
# --------------------------------------------------------------------------- #

def parse_requirements_txt(text):
    pkgs = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
        if m:
            pkgs.append(("PyPI", m.group(1), m.group(2)))
    return pkgs


def parse_package_lock(text):
    data = json.loads(text)
    pkgs = []
    # npm lockfile v2/v3
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        version = meta.get("version")
        if name and version:
            pkgs.append(("npm", name, version))
    # npm lockfile v1 fallback
    if not pkgs:
        def walk(deps):
            for name, meta in (deps or {}).items():
                v = meta.get("version")
                if v:
                    pkgs.append(("npm", name, v))
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return pkgs


def parse_go_mod(text):
    pkgs = []
    in_block = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = line[len("require "):].strip() if line.startswith("require ") else (line if in_block else "")
        m = re.match(r"^([^\s]+)\s+v([0-9][^\s/]+)", target)
        if m:
            pkgs.append(("Go", m.group(1), m.group(2)))
    return pkgs


def parse_gemfile_lock(text):
    pkgs = []
    for line in text.splitlines():
        m = re.match(r"^\s{4}([A-Za-z0-9_\-]+)\s+\(([0-9][^)]+)\)\s*$", line)
        if m:
            pkgs.append(("RubyGems", m.group(1), m.group(2)))
    return pkgs


def parse_poetry_lock(text):
    pkgs, name, version = [], None, None
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            name = version = None
        elif line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"')
            if name and version:
                pkgs.append(("PyPI", name, version))
                name = version = None
    return pkgs


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "poetry.lock": parse_poetry_lock,
}


def detect_and_parse(path):
    base = os.path.basename(path)
    parser = MANIFEST_PARSERS.get(base)
    if parser is None:
        if base.endswith("requirements.txt"):
            parser = parse_requirements_txt
        else:
            raise SystemExit(f"Unsupported manifest '{base}'. Supported: {', '.join(MANIFEST_PARSERS)}")
    with open(path, encoding="utf-8") as fh:
        return parser(fh.read())


def query_osv(packages):
    """Query the OSV.dev batch API. Returns list of (ecosystem,name,version,[vuln_ids])."""
    queries = [{"package": {"ecosystem": eco, "name": name}, "version": ver} for eco, name, ver in packages]
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch", data=payload,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        results = json.load(resp).get("results", [])
    out = []
    for (eco, name, ver), result in zip(packages, results):
        vulns = [v["id"] for v in (result.get("vulns") or [])]
        if vulns:
            out.append((eco, name, ver, vulns))
    return out


def scan_deps(path):
    packages = detect_and_parse(path)
    if not packages:
        return [finding("INFO", "No pinned packages found", f"Could not extract exact-versioned packages from {path}.")]
    findings = []
    try:
        vulnerable = query_osv(packages)
    except (urllib.error.URLError, urllib.error.HTTPError, socket.error) as exc:
        return [finding("INFO", "OSV query failed", f"Could not reach OSV.dev: {exc}. Retry when online.")]
    for eco, name, ver, vuln_ids in vulnerable:
        sev = "HIGH" if len(vuln_ids) > 1 else "MEDIUM"
        findings.append(finding(
            sev, f"Vulnerable dependency: {name}@{ver}",
            f"{eco} package {name} {ver} has {len(vuln_ids)} known advisory(ies): {', '.join(vuln_ids[:8])}"
            + (" ..." if len(vuln_ids) > 8 else ""),
            f"Upgrade {name} to a fixed version. Details: https://osv.dev/vulnerability/{vuln_ids[0]}"))
    if not findings:
        findings.append(finding("INFO", "No known vulnerabilities", f"Checked {len(packages)} package(s); none matched OSV advisories."))
    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def print_report(target, findings):
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("=" * 64)
    print("VULNERABILITY ASSESSMENT REPORT")
    print(f"Target:  {target}")
    print(f"Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("Summary: " + ", ".join(f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: SEV_ORDER.get(s, 9))))
    print("=" * 64)
    for f in findings:
        print(f"\n[{f['severity']}] {f['title']}")
        print(f"  {f['detail']}")
        if f["recommendation"]:
            print(f"  -> {f['recommendation']}")
    actionable = sum(c for s, c in counts.items() if s != "INFO")
    print("\n" + "=" * 64)
    print(f"{actionable} actionable finding(s).")
    return actionable


def main():
    parser = argparse.ArgumentParser(description="Website and software vulnerability scanner")
    sub = parser.add_subparsers(dest="mode", required=True)

    web = sub.add_parser("web", help="Scan a website for header/TLS/cookie weaknesses")
    web.add_argument("url", help="Target URL or hostname (authorized targets only)")
    web.add_argument("--probe", action="store_true",
                     help="Also probe common sensitive paths (active; authorized targets only)")

    deps = sub.add_parser("deps", help="Scan a dependency manifest against OSV.dev")
    deps.add_argument("path", help="Path to requirements.txt, package-lock.json, go.mod, Gemfile.lock, or poetry.lock")

    parser.add_argument("--json", action="store_true", help="Emit findings as JSON instead of text")
    args = parser.parse_args()

    if args.mode == "web":
        target, findings = args.url, scan_web(args.url, probe=args.probe)
    else:
        target, findings = args.path, scan_deps(args.path)

    if args.json:
        print(json.dumps({"target": target, "findings": findings}, indent=2))
        actionable = sum(1 for f in findings if f["severity"] != "INFO")
    else:
        actionable = print_report(target, findings)

    # Non-zero exit when actionable findings exist (useful in CI gates).
    sys.exit(1 if actionable else 0)


if __name__ == "__main__":
    main()
