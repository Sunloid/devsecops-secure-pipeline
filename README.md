# DevSecOps Secure Pipeline

A deliberately vulnerable Flask mini-store used to practise the full **find -> fix -> verify** DevSecOps loop.

> WARNING: The `vulnerable` branch is intentionally insecure. Run it locally only.

## Planted vulnerabilities (`vulnerable` branch)

| # | Flaw | Location | OWASP Top 10 (2021) | Found by (planned) |
|---|------|----------|---------------------|--------------------|
| 1 | SQL injection in login | `app.py` /login | A03 Injection | Bandit/Semgrep, ZAP, sqlmap, IAST |
| 2 | SQL injection in search | `app.py` /search | A03 Injection | Bandit/Semgrep, ZAP, sqlmap, IAST |
| 3 | Reflected XSS in search | `search.html` (`\|safe`) | A03 Injection | Semgrep, ZAP |
| 4 | Hardcoded DB password and secret key | `app.py` | A02 Cryptographic Failures | Bandit/Semgrep, gitleaks |
| 5 | Plain-text passwords in DB | `init_db()` | A02 Cryptographic Failures | Manual review |
| 6 | Outdated dependencies with known CVEs | `requirements.txt` | A06 Vulnerable and Outdated Components | Snyk / Dependency-Check |
| 7 | Debug mode on, verbose DB errors | `app.py` | A05 Security Misconfiguration | Bandit, ZAP |
| 8 | No input validation, no rate limiting on login | `app.py` | A04 Insecure Design / A07 Auth Failures | Manual review |

## Run locally
```bash
pip install -r app/requirements.txt
cd app && python app.py   # http://localhost:5000
```