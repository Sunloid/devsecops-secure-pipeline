# DevSecOps Secure Pipeline

A hands-on DevSecOps project: a deliberately vulnerable Flask web application, paired with a full security toolchain and an automated CI/CD pipeline that finds, fixes, and continuously guards against common web vulnerabilities.

> **Warning:** The `vulnerable` branch (and the pre-fix history on `main`) contains real, working SQL injection, XSS, and other exploitable flaws, planted on purpose for learning. Run it locally only — never deploy it publicly.

![Security Pipeline](https://github.com/Sunloid/devsecops-secure-pipeline/actions/workflows/security.yml/badge.svg)

## What this project demonstrates

- Building and exploiting a vulnerable application by hand (SQL injection, XSS, session forgery)
- Static Application Security Testing (**SAST**) with Bandit and Semgrep
- Software Composition Analysis (**SCA**) with Snyk
- Dynamic Application Security Testing (**DAST**) with OWASP ZAP
- Automated exploitation and verification with sqlmap
- Secrets management with **HashiCorp Vault**
- Continuous security scanning automated with **GitHub Actions**

## Tech stack

| Layer | Tool |
|---|---|
| App | Python, Flask, SQLite |
| SAST | Bandit, Semgrep |
| SCA | Snyk |
| DAST | OWASP ZAP |
| Exploitation proof | sqlmap, flask-unsign |
| Secrets management | HashiCorp Vault (KV v2, dev mode) |
| CI/CD | GitHub Actions |
| Containers | Docker |

## Architecture

```
┌─────────────┐      push/PR       ┌────────────────────────────┐
│  Developer  │ ──────────────────▶│      GitHub Actions          │
└─────────────┘                    │                              │
                                    │  ┌────────┐   ┌───────────┐  │
                                    │  │  SAST  │   │    SCA    │  │
                                    │  │ Bandit │   │   Snyk    │  │
                                    │  │Semgrep │   └───────────┘  │
                                    │  └────────┘                  │
                                    │        │                     │
                                    │        ▼                     │
                                    │  ┌──────────────────────┐    │
                                    │  │        DAST           │    │
                                    │  │  Vault (service) ──▶  │    │
                                    │  │  Flask app (live) ──▶ │    │
                                    │  │  OWASP ZAP             │    │
                                    │  └──────────────────────┘    │
                                    └────────────────────────────┘
```

## Planted vulnerabilities and how each was found

| # | Flaw | OWASP 2021 | CWE | Found by |
|---|---|---|---|---|
| 1 | SQL injection — login bypass | A03 Injection | CWE-89 | Manual test, Bandit, Semgrep, sqlmap |
| 2 | SQL injection — UNION data extraction | A03 Injection | CWE-89 | Manual test, Bandit, Semgrep, sqlmap |
| 3 | Reflected XSS (`\|safe` filter) | A03 Injection | CWE-79 | Manual test, Semgrep |
| 4 | Verbose/raw database error messages | A05 Misconfiguration | CWE-209 | Manual test, ZAP |
| 5 | Flask debug mode enabled | A05 Misconfiguration | CWE-489 | Bandit (HIGH) |
| 6 | Hardcoded database password | A02 Cryptographic Failures | CWE-798 | Bandit, Semgrep |
| 7 | Hardcoded/weak session secret key | A02 / A07 | CWE-798, CWE-321 | Bandit, Semgrep |
| 8 | Plaintext password storage | A02 Cryptographic Failures | CWE-256 | Manual review |
| 9 | Vulnerable/outdated dependencies (Flask, Werkzeug, Jinja2) | A06 Vulnerable Components | CWE-1104 | Snyk (17 issues, 3 HIGH incl. RCE) |
| 10 | No input validation | A03 / A04 | CWE-20 | Manual review |
| 11 | No brute-force protection on login | A07 Auth Failures | CWE-307 | Manual review |
| 12 | Missing CSRF protection / security headers | A05 Misconfiguration | CWE-693, CWE-352 | Semgrep, ZAP |
| 13 | No HTTPS | A02 Cryptographic Failures | CWE-319 | Manual review |

## Before / after scan summary

| Tool | Before | After |
|---|---|---|
| Bandit | B105 x2, B608 x2, B201 x1 | **0 issues** |
| Semgrep | CSRF finding on `login.html`, XSS pattern | Clean (CSRF false-positive documented below) |
| Snyk | 17 open issues (3 HIGH, 12 MEDIUM, 2 LOW) across Flask 2.0.1 / Werkzeug 2.0.1 / Jinja2 3.0.1 | **0 issues** after upgrading to Flask 3.1.3 / Werkzeug 3.1.9 / Jinja2 3.1.6 |
| ZAP (baseline) | SQLi/XSS exploitable, missing headers, no CSRF token | 0 FAIL, 12 minor WARN (missing security headers only) |
| sqlmap | `users` table dumped (plaintext passwords) via `/search` | "parameter does not appear to be injectable" |

Full scan reports and screenshots: [`docs/before/`](docs/before) and [`docs/after/`](docs/after).

## Fixes applied

- **SQL injection (flaws 1, 2):** replaced string-concatenated queries with parameterized queries (`?` placeholders) in `/login` and `/search`.
- **XSS (flaw 3):** removed the `|safe` filter in `search.html` so Jinja2's default auto-escaping applies.
- **Debug mode (flaw 5):** `debug=False`, bound to `127.0.0.1` instead of `0.0.0.0`.
- **CSRF (flaw 12):** added Flask-WTF's `CSRFProtect`, with a hidden `csrf_token()` field on the login form. Verified with a token-less `curl` POST, correctly rejected with "The CSRF token is missing."
- **Outdated dependencies (flaw 9):** upgraded Flask, Werkzeug, and Jinja2 to the versions Snyk identified as fixed, resolving all 17 findings including a HIGH-severity RCE in Werkzeug.
- **Hardcoded secrets (flaws 6, 7):** both `DB_PASSWORD` and `app.secret_key` are now fetched from HashiCorp Vault at application startup via the `hvac` client — no secret values exist in source code.

### Known false positive

Semgrep's `python.django.security.django-no-csrf-token` rule continues to flag `login.html` even after CSRF protection was correctly added, because the rule pattern-matches Django's `{% csrf_token %}` syntax and doesn't recognize Flask-WTF's `{{ csrf_token() }}`. Verified as a false positive via manual testing (see above) rather than suppressed blindly.

## Secrets management with Vault

Both the Flask session signing key and the (simulated) database password are stored in Vault's KV v2 engine and fetched at runtime:

```python
client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
secret = client.secrets.kv.v2.read_secret_version(path="flask-app")
app.secret_key = secret["data"]["data"]["secret_key"]
DB_PASSWORD = secret["data"]["data"]["db_password"]
```

Vault runs in **dev mode** for local and CI demonstration purposes. Dev mode stores secrets in memory only, so they do not persist across container restarts — a production deployment would use a persistent storage backend (Raft, Consul, or cloud storage), a proper seal/unseal procedure, and short-lived, identity-scoped tokens instead of one static root token.

## CI/CD pipeline

`.github/workflows/security.yml` runs on every push and pull request to `main`:

- **`sast`** — Bandit and Semgrep against the application code
- **`sca`** — Snyk against `requirements.txt`, failing on high-severity findings
- **`dast`** — spins up a Vault service container, seeds test secrets, starts the Flask app, then runs an OWASP ZAP baseline scan against the live instance

All three jobs run independently and report pass/fail per job in the GitHub Actions tab, so a failure points directly to which category of check (code, dependencies, or live behavior) needs attention.

## Running it locally

```bash
git clone https://github.com/Sunloid/devsecops-secure-pipeline.git
cd devsecops-secure-pipeline
python -m venv venv
.\venv\Scripts\activate
pip install -r app/requirements.txt

# Start Vault (dev mode)
docker run --cap-add=IPC_LOCK -d --name=vault-dev -p 8200:8200 \
  -e "VAULT_DEV_ROOT_TOKEN_ID=myroot" \
  -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
  hashicorp/vault

docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='myroot' vault-dev \
  vault kv put secret/flask-app secret_key="<generate-with-secrets.token_hex(32)>" db_password="SuperSecret123!"

$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "myroot"

cd app
python app.py
```

Visit `http://localhost:5000`. To see the original vulnerable version, check out the `vulnerable` branch instead.

## Lessons learned

- A SAST tool's rule naming/origin matters — a "Django" rule firing on Flask code is a real false positive, not a bug in your code, and should be verified rather than trusted blindly.
- DAST baseline (passive) scans reliably catch header/config issues but can miss form-based SQL injection — pairing ZAP with sqlmap closed that gap.
- "It works on my machine" often hides an undeclared dependency (`hvac` was installed locally but missing from `requirements.txt`) — CI caught this immediately on first run.
- Dependency version pins need to move together: upgrading Flask's major version surfaced transitive conflicts (`click`, `itsdangerous`) that had to be resolved one at a time.
- Vault's dev mode is memory-only and does not survive container restarts — fine for local/CI demos, explicitly not for production.

## Project structure

```
devsecops-secure-pipeline/
├── app/
│   ├── app.py
│   ├── requirements.txt
│   ├── templates/
│   └── static/
├── docs/
│   ├── before/        # pre-fix scan evidence
│   └── after/         # post-fix scan evidence
├── .github/
│   └── workflows/
│       └── security.yml
└── README.md
```