---
name: assessing-website-and-software-vulnerabilities
description: 'Checks websites and software for security vulnerabilities. Runs passive
  web checks (HTTP security headers, TLS/certificate posture, cookie attributes, and
  optional sensitive-path probing) and software composition analysis that resolves
  dependency versions from manifests/lockfiles and queries the OSV.dev database for
  known CVEs. Use when you need a fast, authorized first-pass vulnerability assessment
  of a web application and its dependencies, a CI/CD security gate, or a triage step
  before deeper penetration testing.

  '
domain: cybersecurity
subdomain: vulnerability-management
tags:
- vulnerability-assessment
- web-security
- security-headers
- tls
- software-composition-analysis
- dependency-scanning
- osv
- cve
- devsecops
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- DE.CM-08
- ID.RA-08
- PR.PS-02
mitre_attack:
- T1595.002
- T1592.002
- T1190
---
# Assessing Website and Software Vulnerabilities

## When to Use

Use this skill when:
- You need a quick, **authorized** first-pass vulnerability check of a website and the software/dependencies behind it.
- You want a CI/CD gate that fails a build when a web target is missing security controls or a dependency has a known CVE.
- You are triaging a target before committing to a deeper engagement and want to know where to focus.

**Do not use** this skill to scan systems you do not own or lack written authorization to test. This is a defensive/assessment tool, not an exploitation framework — it identifies weaknesses, it does not attack them.

## Authorization (read first)

Only run against assets you own or are explicitly authorized to assess. The bundled scanner's default web checks are passive (a normal HTTPS request plus a TLS handshake), but the `--probe` option actively requests specific paths and must be enabled deliberately. Keep scope, authorization, and timing agreed in writing before scanning third-party systems.

## Prerequisites

- Python 3.8+ (the scanner uses only the standard library — no packages to install).
- Outbound HTTPS access to the target (web mode) and to `https://api.osv.dev` (dependency mode).
- A dependency manifest or lockfile for software mode: `requirements.txt`, `package-lock.json`, `go.mod`, `Gemfile.lock`, or `poetry.lock`.

## Workflow

### Step 1: Assess the website

Run the passive web checks against the target. This analyses HTTP security headers, the TLS certificate and negotiated protocol, and cookie attributes:

```bash
python scripts/vuln_scan.py web https://target.example.com
```

What it flags:

| Check | Example finding | Severity |
|-------|-----------------|----------|
| Missing `Strict-Transport-Security` / `Content-Security-Policy` | HSTS/CSP absent | HIGH |
| Missing `X-Content-Type-Options` / `X-Frame-Options` | sniffing / clickjacking exposure | MEDIUM |
| Expired or invalid TLS certificate | cert expired N days ago | CRITICAL / HIGH |
| Outdated TLS protocol (TLS 1.1 or below) | server negotiated TLSv1.1 | HIGH |
| Plain HTTP (no encryption) | served over HTTP | HIGH |
| Weak cookie flags (`Secure`/`HttpOnly`/`SameSite`) | session cookie missing flags | MEDIUM |
| Information disclosure (`Server`, `X-Powered-By`) | version banner leaked | LOW |

### Step 2: Probe for exposed resources (optional, active)

Only with authorization, add `--probe` to check a short list of commonly-exposed sensitive paths (`/.git/config`, `/.env`, `/server-status`, etc.):

```bash
python scripts/vuln_scan.py web https://target.example.com --probe
```

### Step 3: Assess the software dependencies

Point the scanner at a manifest or lockfile. It resolves exact versions and queries OSV.dev for known advisories:

```bash
python scripts/vuln_scan.py deps ./requirements.txt
python scripts/vuln_scan.py deps ./package-lock.json
python scripts/vuln_scan.py deps ./go.mod
```

Each vulnerable package is reported with its advisory IDs and an OSV link for remediation guidance.

### Step 4: Gate or report

The scanner exits non-zero when actionable (non-INFO) findings exist, so it drops straight into a pipeline:

```bash
python scripts/vuln_scan.py deps requirements.txt || echo "Build failed: vulnerable dependencies"
```

For machine-readable output (dashboards, ticketing, SIEM ingestion), add `--json`:

```bash
python scripts/vuln_scan.py web https://target.example.com --json > web_findings.json
```

### Step 5: Prioritize and remediate

Triage findings highest-severity first. Confirm exploitability and business impact before raising tickets, and apply remediation SLAs (see the related skills below for CVSS/EPSS/KEV-based prioritization and SLA tracking).

## Going Deeper

This skill is a fast first pass. For thorough assessments, chain it with the specialized skills in this library:

- **Web app depth**: `performing-web-application-penetration-test`, `performing-security-headers-audit`, `performing-ssl-tls-security-assessment`, `testing-for-xss-vulnerabilities`, `exploiting-sql-injection-vulnerabilities`.
- **Network/host**: `scanning-network-with-nmap-advanced`, `performing-vulnerability-scanning-with-nessus`, `performing-authenticated-vulnerability-scan`.
- **Software supply chain**: `performing-sca-dependency-scanning-with-snyk`, `scanning-docker-images-with-trivy`, `analyzing-sbom-for-supply-chain-vulnerabilities`, `implementing-secrets-scanning-in-ci-cd`.
- **Prioritization & tracking**: `prioritizing-vulnerabilities-with-cvss-scoring`, `implementing-epss-score-for-vulnerability-prioritization`, `performing-cve-prioritization-with-kev-catalog`, `building-vulnerability-scanning-workflow`.

## Key Concepts

| Term | Definition |
|------|-----------|
| **Security headers** | HTTP response headers (HSTS, CSP, X-Frame-Options, etc.) that instruct browsers to enforce protections against common web attacks. |
| **SCA** | Software Composition Analysis — identifying known-vulnerable components by matching dependency versions against advisory databases. |
| **OSV.dev** | Open Source Vulnerabilities — a free, aggregated vulnerability database with a public batch API spanning PyPI, npm, Go, RubyGems, Maven, and more. |
| **Passive vs active** | Passive checks read normally-returned data; active checks (like `--probe`) send requests that solicit specific behavior and require explicit authorization. |
| **CI gate** | A pipeline step that fails the build when security criteria are not met (here, a non-zero exit on actionable findings). |

## Tools & Systems

- **scripts/vuln_scan.py**: the bundled, dependency-free scanner (`web` and `deps` modes).
- **OSV.dev API**: `https://api.osv.dev/v1/querybatch` for known-vulnerability lookups.
- **Standard library only**: `urllib`, `ssl`, `socket`, `json` — runs anywhere Python 3.8+ is available, including locked-down CI runners.

## Output Format

```
================================================================
VULNERABILITY ASSESSMENT REPORT
Target:  https://target.example.com
Scanned: 2026-06-14 19:30 UTC
Summary: 2 HIGH, 2 MEDIUM, 1 LOW, 1 INFO
================================================================

[HIGH] Missing header: content-security-policy
  Response from https://target.example.com (HTTP 200) omits 'content-security-policy'.
  -> Define a CSP to mitigate XSS and data injection.

[MEDIUM] Weak cookie flags: session
  Cookie 'session' is missing: httponly, samesite.
  -> Set Secure, HttpOnly, and an explicit SameSite attribute on session cookies.

================================================================
5 actionable finding(s).
```
