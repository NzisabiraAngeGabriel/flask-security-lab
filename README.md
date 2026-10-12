# Flask Security Lab

An educational security laboratory built with Flask and SQLite.
Two builds of the same application run side by side:

- **vulnerable/** — port 5000 — intentionally contains four
  isolated security weaknesses for controlled local testing.
- **secure/** — port 5001 — the same application with the
  corresponding fixes applied.

## Vulnerabilities demonstrated

| # | Vulnerability | Vulnerable endpoint | Secure fix |
|---|---|---|---|
| 1 | SQL Injection | `GET /search?q=` | Parameterized query (`?` placeholder) |
| 2 | Stored XSS | `POST /comments` (`body`) | Output encoding; CSP header |
| 3 | OS Command Injection | `POST /diagnostic` (`host`) | Allowlist regex; `subprocess` argument vector with `shell=False` |
| 4 | Directory Traversal | `GET /resource?file=` | Basename check; DB allowlist; `realpath` containment |

## Running locally

    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

    python vulnerable\app.py       # http://127.0.0.1:5000
    python secure\app.py           # http://127.0.0.1:5001

Seed credentials: `alice / password123`, `bob / hunter2`.

## Safety boundary

This is an educational laboratory and must never be exposed
on a shared network. In its default configuration both apps
bind to loopback (`127.0.0.1`) and only serve clients on the
local machine. Do not run them on a public or untrusted
network without changing the bind address deliberately and
understanding the consequences.

All test payloads target only the local application.