"""
SwiftBank — Intentionally Vulnerable Demo

A personal banking / online bank dashboard built on Flask + SQLite, deliberately
seeded with vulnerabilities for cybersecurity product demos.

WARNING: Do NOT deploy. Run only on localhost / isolated lab.
See README.md for the full vulnerability catalogue.
"""

import base64
import csv
import io
import os
import pickle
import random
import sqlite3
import subprocess
import threading
import time
import yaml
from urllib.parse import urlparse

import jwt
import requests
from lxml import etree
from flask import (
    Flask, g, request, redirect, url_for, render_template,
    render_template_string, make_response, jsonify, send_file, abort,
    session, Response
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "swiftbank.db")
UPLOADS = os.path.join(APP_DIR, "uploads")
IMPORTS = os.path.join(APP_DIR, "imports")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(IMPORTS, exist_ok=True)

# VULN #1 — Hardcoded, weak Flask secret key. Flask sessions are signed with this,
# so an attacker who guesses it can forge any session cookie.
SECRET_KEY = "dev"

# VULN #2 — Hardcoded JWT signing key, committed in source.
# FIX: Read from environment variable; fail if not set in production.
JWT_KEY = os.environ.get("JWT_SECRET_KEY", None)
if JWT_KEY is None:
    # Provide a clear error so deployers know to set it, rather than silently falling
    # back to a weak default. In demo/lab mode a warning is printed.
    if os.environ.get("SWIFTBANK_INSECURE_DEMO"):
        JWT_KEY = "swiftbank-jwt-2025"
        import warnings
        warnings.warn("Using hardcoded demo JWT key. Set JWT_SECRET_KEY env var for production.")
    else:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not set. "
            "Set it to a strong random secret, or set SWIFTBANK_INSECURE_DEMO=1 to use the insecure default."
        )

# VULN #3 — Hardcoded admin backdoor token honored anywhere `X-Admin-Token` header is sent.
ADMIN_BACKDOOR = "let-me-in-please"

app = Flask(__name__)
app.secret_key = SECRET_KEY
# VULN #4 — Debug mode left on in "production". Exposes Werkzeug debugger console at /console
# when an exception is hit (deliberately reachable below). Also leaks tracebacks.
app.debug = True
# VULN #5 — Session cookie is NOT httpOnly/secure/sameSite, so document.cookie steals it.
app.config.update(
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE=None,
)

# ----------------- DB helpers -----------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,           -- plaintext on purpose
        full_name TEXT,
        email TEXT,
        ssn TEXT,                         -- sensitive PII
        role TEXT DEFAULT 'customer',
        avatar TEXT DEFAULT '/static/img/default-avatar.svg',
        bio TEXT,
        reset_token TEXT,
        otp TEXT
    );
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        number TEXT UNIQUE NOT NULL,
        name TEXT,
        kind TEXT,
        balance REAL DEFAULT 0,
        currency TEXT DEFAULT 'EUR'
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_account INTEGER,
        to_account INTEGER,
        amount REAL,
        memo TEXT,
        kind TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS payees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        nickname TEXT,
        account_number TEXT,
        bank TEXT
    );
    CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        subject TEXT,
        body TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS jwt_keys (
        id TEXT PRIMARY KEY,
        secret TEXT NOT NULL
    );
    """)
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ("admin",   "admin2025",   "Bank Admin",       "admin@swiftbank.local", "000-00-0000", "admin"),
            ("johndoe", "P@ssw0rd",    "John Doe",         "john@example.com",      "111-22-3333", "customer"),
            ("janedoe", "spring2025",  "Jane Doe",         "jane@example.com",      "222-33-4444", "customer"),
            ("emma",    "letmein",     "Emma Brown",       "emma@example.com",      "333-44-5555", "customer"),
            ("mark",    "hunter2",     "Mark Lewis",       "mark@example.com",      "444-55-6666", "customer"),
        ]
        cur.executemany("INSERT INTO users (username,password,full_name,email,ssn,role) VALUES (?,?,?,?,?,?)", users)
        accounts = [
            (1, "ES00-0000-0000-0001", "House Account",   "checking",  9_999_999.00),
            (2, "ES12-3456-7890-0002", "Main Checking",   "checking",  4_320.55),
            (2, "ES12-3456-7890-0003", "Savings",         "savings",  18_750.00),
            (3, "ES99-1111-2222-0004", "Everyday",        "checking",  2_180.10),
            (3, "ES99-1111-2222-0005", "Vacation Fund",   "savings",   6_400.00),
            (4, "ES55-7777-8888-0006", "Checking",        "checking",    150.00),
            (5, "ES44-3333-2222-0007", "Checking",        "checking",  1_020.40),
        ]
        cur.executemany("INSERT INTO accounts (user_id,number,name,kind,balance) VALUES (?,?,?,?,?)", accounts)
        txns = [
            (2, 4, 120.0, "Dinner",       "transfer"),
            (4, 2, 80.0,  "Tickets",      "transfer"),
            (2, 3, 500.0, "To savings",   "internal"),
            (3, 5, 200.0, "Loan repay",   "transfer"),
            (None, 2, 2500.0, "Salary March 2026", "deposit"),
            (None, 4, 1900.0, "Salary March 2026", "deposit"),
        ]
        cur.executemany("INSERT INTO transactions (from_account,to_account,amount,memo,kind) VALUES (?,?,?,?,?)", txns)
        payees = [
            (2, "Jane (friend)",    "ES99-1111-2222-0004", "SwiftBank"),
            (2, "Landlord",         "DE00-9999-1111-2222", "Deutsche Bank"),
            (3, "Mom",              "ES44-3333-2222-0007", "SwiftBank"),
        ]
        cur.executemany("INSERT INTO payees (user_id,nickname,account_number,bank) VALUES (?,?,?,?)", payees)
        # JWT signing keys with kid lookup — used by /api/balance to demo kid-SQLi
        cur.execute("INSERT OR REPLACE INTO jwt_keys (id,secret) VALUES (?,?)", ("default", JWT_KEY))
        conn.commit()
    conn.close()


init_db()

# ----------------- Auth helpers -----------------

def current_user():
    """Identity resolution. VULN #6 — we trust an unsigned `uid` cookie as a fallback,
    so anyone can become any user by setting Cookie: uid=N. The proper Flask session
    cookie is also available, but the fallback is the easy win."""
    uid = session.get("uid")
    if not uid:
        try:
            uid = int(request.cookies.get("uid", "0"))
        except ValueError:
            uid = 0
    if not uid:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return dict(row) if row else None


def require_login(view):
    from functools import wraps
    @wraps(view)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            # VULN #7 — `next` param is reflected straight into a redirect with no host check (open redirect).
            return redirect(url_for("login", next=request.full_path))
        g.user = u
        return view(*a, **kw)
    return wrapper


# ----------------- Misc context -----------------

@app.context_processor
def inject_user():
    return {"user": current_user()}


# VULN #8 — Permissive CORS with credentials. Any origin can read responses.
@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    # VULN #9 — Security headers omitted (no CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
    return resp


# ----------------- Public pages -----------------

@app.route("/")
def index():
    courts = get_db().execute("SELECT id,number,name,kind,balance FROM accounts WHERE user_id = 1").fetchall()
    return render_template("index.html", featured=courts)


# VULN #10 — Account-number enumeration. The lookup endpoint reveals whether a given
# account number exists at SwiftBank (different status / shape per case), enabling a
# scripted enumeration to harvest valid accounts before targeted attacks.
@app.route("/api/account-lookup")
def account_lookup():
    n = request.args.get("number", "")
    row = get_db().execute("SELECT a.number,u.full_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.number = ?", (n,)).fetchone()
    if row:
        return jsonify({"exists": True, "holder": row["full_name"], "number": row["number"]})
    return jsonify({"exists": False}), 404


# ----------------- Auth -----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = request.values.get("next") or "/dashboard"
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # VULN #11 — SQL injection in login: classic string-concat query, no parameters.
        # Payload: username = `admin' -- ` password = anything → bypass.
        sql = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
        try:
            row = get_db().execute(sql).fetchone()
        except sqlite3.Error as e:
            # VULN #12 — verbose SQL error returned to the browser.
            return f"<pre>SQL error: {e}\nquery: {sql}</pre>", 500
        if not row:
            # VULN #13 — username enumeration via distinct error messages.
            exists = get_db().execute("SELECT 1 FROM users WHERE username = ?", (u,)).fetchone()
            error = "Wrong password" if exists else "No such user"
        else:
            # VULN #14 — 2FA OTP is generated with `random.randint` (predictable PRNG, not
            # `secrets`), AND the chosen OTP is echoed in the page as a "convenience hint"
            # for the demo, so attackers can read it from the response.
            otp = str(random.randint(1000, 9999))
            get_db().execute("UPDATE users SET otp = ? WHERE id = ?", (otp, row["id"]))
            get_db().commit()
            session["pending_uid"] = row["id"]
            return render_template("otp.html", hint=otp, next=nxt)
    return render_template("login.html", error=error, next=nxt)


@app.route("/otp", methods=["POST"])
def otp():
    code = request.form.get("code", "")
    uid = session.get("pending_uid")
    nxt = request.form.get("next") or "/dashboard"
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
    if not row:
        return redirect(url_for("login"))
    # VULN #15 — no rate limit / lockout on OTP attempts (4 digits = 10k brute force).
    if code != (row["otp"] or ""):
        return render_template("otp.html", hint=row["otp"], next=nxt, error="Bad code")
    session.pop("pending_uid", None)
    session["uid"] = row["id"]
    # VULN #16 — uid also written to a plain cookie (no signing) → see current_user fallback.
    resp = make_response(redirect(nxt))  # VULN #17 — open redirect via `next`.
    resp.set_cookie("uid", str(row["id"]))
    # VULN #18 — JWT signed with hardcoded HS256 key, `kid` header used for key lookup.
    token = jwt.encode({"sub": row["id"], "role": row["role"]}, JWT_KEY, algorithm="HS256", headers={"kid": "default"})
    resp.set_cookie("token", token)
    return resp


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect("/"))
    resp.delete_cookie("uid")
    resp.delete_cookie("token")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # VULN #19 — Mass assignment. `role` and `balance` accepted from the request,
        # so registering with role=admin elevates instantly; balance opens an account
        # with arbitrary starting funds.
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        full = request.form.get("full_name", "")
        email = request.form.get("email", "")
        role = request.form.get("role") or "customer"
        balance = float(request.form.get("balance") or 0)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,password,full_name,email,role) VALUES (?,?,?,?,?)",
                       (u, p, full, email, role))
            uid = db.execute("SELECT id FROM users WHERE username = ?", (u,)).fetchone()["id"]
            num = f"ES{random.randint(10,99)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{uid:04d}"
            db.execute("INSERT INTO accounts (user_id,number,name,kind,balance) VALUES (?,?,?,?,?)",
                       (uid, num, "Checking", "checking", balance))
            db.commit()
        except sqlite3.IntegrityError as e:
            return render_template("register.html", error=str(e))
        session["uid"] = uid
        return redirect("/dashboard")
    return render_template("register.html", error=None)


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        u = request.form.get("username", "")
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        if not row:
            return render_template("forgot.html", error="No such user", token=None)
        # VULN #20 — Predictable reset token: based on time + username, not cryptographically
        # secure. Easy to predict / replay.
        token = base64.urlsafe_b64encode(f"{int(time.time())}:{u}".encode()).decode()
        get_db().execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, row["id"]))
        get_db().commit()
        # Token is "emailed" — but we just show it on screen for the demo.
        return render_template("forgot.html", error=None, token=token)
    return render_template("forgot.html", error=None, token=None)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    token = request.values.get("token", "")
    row = get_db().execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()
    if not row:
        return "Invalid token", 400
    if request.method == "POST":
        np = request.form.get("password", "")
        get_db().execute("UPDATE users SET password = ?, reset_token = NULL WHERE id = ?", (np, row["id"]))
        get_db().commit()
        return redirect("/login")
    return render_template("reset.html", token=token, username=row["username"])


# ----------------- Dashboard -----------------

@app.route("/dashboard")
@require_login
def dashboard():
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", (g.user["id"],)).fetchall()
    # Recent txns across the user's accounts. Memo is rendered raw in the template.
    ids = [a["id"] for a in accounts] or [-1]
    qmarks = ",".join("?" * len(ids))
    txns = db.execute(
        f"SELECT t.*, fa.number AS from_num, ta.number AS to_num "
        f"FROM transactions t "
        f"LEFT JOIN accounts fa ON fa.id = t.from_account "
        f"LEFT JOIN accounts ta ON ta.id = t.to_account "
        f"WHERE t.from_account IN ({qmarks}) OR t.to_account IN ({qmarks}) "
        f"ORDER BY t.id DESC LIMIT 20",
        ids + ids
    ).fetchall()
    return render_template("dashboard.html", accounts=accounts, txns=txns)


# VULN #21 — IDOR: any logged-in user can read any account by its numeric ID. No ownership check.
@app.route("/account/<int:aid>")
@require_login
def account(aid):
    db = get_db()
    a = db.execute("SELECT * FROM accounts WHERE id = ?", (aid,)).fetchone()
    if not a:
        return "Not found", 404
    txns = db.execute(
        "SELECT t.*, fa.number AS from_num, ta.number AS to_num "
        "FROM transactions t "
        "LEFT JOIN accounts fa ON fa.id = t.from_account "
        "LEFT JOIN accounts ta ON ta.id = t.to_account "
        "WHERE t.from_account = ? OR t.to_account = ? ORDER BY t.id DESC",
        (aid, aid)
    ).fetchall()
    return render_template("account.html", account=a, txns=txns)


# ----------------- Transfer -----------------

# In-memory "lock" we intentionally DO NOT use, so the read-then-write pattern races.
_io_sleep = 0.4  # makes the race window obvious for the demo


@app.route("/transfer", methods=["GET", "POST"])
@require_login
def transfer():
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", (g.user["id"],)).fetchall()
    payees = db.execute("SELECT * FROM payees WHERE user_id = ?", (g.user["id"],)).fetchall()
    if request.method == "POST":
        from_id = int(request.form.get("from_id"))
        to_number = request.form.get("to_number", "").strip()
        # VULN #22 — Negative-amount transfer. `amount` is cast to float without a >0 check,
        # so submitting amount=-500 reverses the flow and pulls money from the recipient.
        amount = float(request.form.get("amount") or 0)
        memo = request.form.get("memo", "")
        # VULN #23 — IDOR on `from_id`: no check that the source account belongs to the user.
        src = db.execute("SELECT * FROM accounts WHERE id = ?", (from_id,)).fetchone()
        if not src:
            return render_template("transfer.html", accounts=accounts, payees=payees, error="Source not found")
        dst = db.execute("SELECT * FROM accounts WHERE number = ?", (to_number,)).fetchone()
        if not dst:
            return render_template("transfer.html", accounts=accounts, payees=payees, error="Destination not found")
        # VULN #24 — TOCTOU race: read balance, sleep, write. Two concurrent transfers
        # of the full balance both pass the check.
        cur_balance = src["balance"]
        if cur_balance < amount:
            return render_template("transfer.html", accounts=accounts, payees=payees, error="Insufficient funds")
        time.sleep(_io_sleep)
        db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, src["id"]))
        db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, dst["id"]))
        db.execute("INSERT INTO transactions (from_account,to_account,amount,memo,kind) VALUES (?,?,?,?,?)",
                   (src["id"], dst["id"], amount, memo, "transfer"))
        db.commit()
        return redirect("/dashboard")
    return render_template("transfer.html", accounts=accounts, payees=payees, error=None)


# ----------------- Statement download -----------------

# VULN #25 — Path traversal in the statement download. `name` is joined into a path
# without sanitization. Use `?name=../../../etc/passwd` (absolute) or `?name=../app.py`.
@app.route("/statement/download")
@require_login
def statement_download():
    name = request.args.get("name", "march-2026.csv")
    full = os.path.abspath(os.path.join(IMPORTS, name))
    if not os.path.exists(full):
        return f"<pre>Not found: {full}</pre>", 404
    return send_file(full, as_attachment=True)


# VULN #26 — CSV / formula injection. Transaction memos are written into the CSV as-is.
# A memo like `=cmd|'/C calc'!A1` (or `@SUM(...)`) executes when opened in Excel.
@app.route("/statement/export")
@require_login
def statement_export():
    db = get_db()
    ids = [a["id"] for a in db.execute("SELECT id FROM accounts WHERE user_id = ?", (g.user["id"],)).fetchall()] or [-1]
    qmarks = ",".join("?" * len(ids))
    rows = db.execute(
        f"SELECT created_at, amount, memo FROM transactions "
        f"WHERE from_account IN ({qmarks}) OR to_account IN ({qmarks})",
        ids + ids
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["date", "amount", "memo"])
    for r in rows:
        w.writerow([r["created_at"], r["amount"], r["memo"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=statement.csv"})


# VULN #27 — XXE in XML statement import. lxml's parser has resolve_entities=True by default
# and we pass no_network=False, so an external DTD or SYSTEM entity will be fetched / read.
# Payload (POST body, content-type text/xml):
#   <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
@app.route("/statement/import", methods=["GET", "POST"])
@require_login
def statement_import():
    result = None
    error = None
    if request.method == "POST":
        body = request.data or request.form.get("xml", "").encode()
        try:
            parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
            doc = etree.fromstring(body, parser)
            result = etree.tostring(doc, pretty_print=True).decode()
        except Exception as e:
            error = str(e)
    return render_template("statement_import.html", result=result, error=error)


# ----------------- Profile -----------------

@app.route("/profile", methods=["GET", "POST"])
@require_login
def profile():
    db = get_db()
    if request.method == "POST":
        # VULN #28 — Mass assignment via Object-style update. Any column in the whitelist
        # may be set, including `role`. Stored XSS via `bio` rendered raw in the view.
        allowed = ["full_name", "email", "bio", "role", "password", "ssn"]
        sets, vals = [], []
        for k in allowed:
            if k in request.form:
                sets.append(f"{k} = ?")
                vals.append(request.form[k])
        if sets:
            vals.append(g.user["id"])
            db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
            db.commit()
        return redirect("/profile")
    me = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    return render_template("profile.html", me=me)


# VULN #29 — Unrestricted file upload. Any extension is accepted, the original filename is
# kept, and the upload directory is served as static. Upload `pwn.html` containing
# <script>...</script> and visit /uploads/pwn.html for same-origin script execution.
@app.route("/profile/avatar", methods=["POST"])
@require_login
def avatar():
    f = request.files.get("avatar")
    if not f:
        return redirect("/profile")
    dest = os.path.join(UPLOADS, f.filename)
    f.save(dest)
    get_db().execute("UPDATE users SET avatar = ? WHERE id = ?", (f"/uploads/{f.filename}", g.user["id"]))
    get_db().commit()
    return redirect("/profile")


@app.route("/uploads/<path:fn>")
def uploads(fn):
    # Static-style serve. No content-type sniffing protection.
    return send_file(os.path.join(UPLOADS, fn))


# ----------------- Support ticket — SSTI -----------------

# VULN #30 — Server-Side Template Injection (SSTI) in Jinja2.
# `subject` is rendered through `render_template_string` so a payload like
# `{{ config }}` or `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`
# is evaluated server-side. Used here to "preview" the support email.
@app.route("/support", methods=["GET", "POST"])
@require_login
def support():
    preview = None
    if request.method == "POST":
        subject = request.form.get("subject", "")
        body = request.form.get("body", "")
        # Preview = template-render the subject so the user can "use {{ user.full_name }}".
        preview = render_template_string(
            "<h3>" + subject + "</h3><p>From {{ user.full_name }}</p><pre>" + body + "</pre>"
        )
        get_db().execute("INSERT INTO support_tickets (user_id,subject,body) VALUES (?,?,?)",
                         (g.user["id"], subject, body))
        get_db().commit()
    return render_template("support.html", preview=preview)


# ----------------- Saved searches — pickle RCE -----------------

# VULN #31 — Insecure deserialization. A cookie called `prefs` is base64-encoded, pickled
# user preferences. `pickle.loads` on untrusted data is RCE. Craft a payload with a
# `__reduce__` returning `(os.system, ("cmd",))`.
@app.route("/transactions")
@require_login
def transactions():
    raw = request.cookies.get("prefs")
    prefs = {"sort": "date", "limit": 50}
    if raw:
        try:
            prefs = pickle.loads(base64.b64decode(raw))  # noqa: S301
        except Exception:
            pass
    db = get_db()
    ids = [a["id"] for a in db.execute("SELECT id FROM accounts WHERE user_id = ?", (g.user["id"],)).fetchall()] or [-1]
    qmarks = ",".join("?" * len(ids))
    # VULN #32 — `sort` is concatenated into SQL → second-order SQLi via the cookie.
    sort = prefs.get("sort", "id")
    limit = int(prefs.get("limit") or 50)
    rows = db.execute(
        f"SELECT t.*, fa.number AS from_num, ta.number AS to_num FROM transactions t "
        f"LEFT JOIN accounts fa ON fa.id = t.from_account "
        f"LEFT JOIN accounts ta ON ta.id = t.to_account "
        f"WHERE t.from_account IN ({qmarks}) OR t.to_account IN ({qmarks}) "
        f"ORDER BY {sort} LIMIT {limit}",
        ids + ids
    ).fetchall()
    resp = make_response(render_template("transactions.html", txns=rows, prefs=prefs))
    if not raw:
        resp.set_cookie("prefs", base64.b64encode(pickle.dumps(prefs)).decode())
    return resp


# ----------------- API -----------------

# VULN #33 — JWT `kid` SQL injection. The kid header is concatenated into a SQL lookup
# for the signing key, so a forged kid like `' UNION SELECT 'attacker-key' --` lets the
# attacker pick the verification key (and therefore forge any token).
@app.route("/api/balance")
def api_balance():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")
    # Also accept admin backdoor token (VULN #34)
    if request.headers.get("X-Admin-Token") == ADMIN_BACKDOOR:
        rows = get_db().execute("SELECT number,balance FROM accounts").fetchall()
        return jsonify([dict(r) for r in rows])
    if not token:
        return jsonify({"error": "no token"}), 401
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid", "default")
        row = get_db().execute(f"SELECT secret FROM jwt_keys WHERE id = '{kid}'").fetchone()  # SQLi
        if not row:
            return jsonify({"error": "unknown kid"}), 401
        # VULN #35 — `alg:none` accepted alongside HS256.
        if header.get("alg") == "none":
            payload = jwt.decode(token, options={"verify_signature": False})
        else:
            payload = jwt.decode(token, row["secret"], algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": str(e)}), 401
    accounts = get_db().execute("SELECT number,name,kind,balance FROM accounts WHERE user_id = ?",
                                (payload["sub"],)).fetchall()
    return jsonify([dict(a) for a in accounts])


# VULN #36 — Excessive data exposure: API returns password, ssn, otp, reset_token.
@app.route("/api/users")
@require_login
def api_users():
    rows = get_db().execute("SELECT id,username,password,ssn,email,role,otp,reset_token FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


# ----------------- Admin -----------------

def is_admin():
    """Demo authorization. VULN #37 — the X-Admin-Token header is also accepted,
    and there is NO server-side role check on the admin pages themselves — only this
    helper, which we call inconsistently. Several admin routes skip the check entirely."""
    if request.headers.get("X-Admin-Token") == ADMIN_BACKDOOR:
        return True
    u = current_user()
    return bool(u and u.get("role") == "admin")


@app.route("/admin")
@require_login
def admin():
    # VULN #38 — Admin dashboard does not actually enforce `is_admin()`. Any logged-in
    # user can reach it just by visiting the URL.
    db = get_db()
    users = db.execute("SELECT id,username,full_name,email,role,ssn FROM users").fetchall()
    accounts = db.execute("SELECT a.*, u.username FROM accounts a JOIN users u ON u.id=a.user_id").fetchall()
    return render_template("admin.html", users=users, accounts=accounts)


# VULN #39 — Command injection in admin ping (shell=True with string concat).
import re

@app.route("/admin/ping")
@require_login
def admin_ping():
    host = request.args.get("host", "127.0.0.1")
    # Validate host is a safe IP address or hostname (alphanumeric, dots, hyphens)
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        return render_template("admin_result.html", title="Ping", output="Invalid host")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return render_template("admin_result.html", title="Ping", output=out.stdout + out.stderr)



# `file://`, internal IPs, cloud metadata IPs are all reachable.
@app.route("/admin/verify-bank")
@require_login
def admin_verify():
    url = request.args.get("url", "")
    try:
        # NOTE: requests doesn't support file:// natively; we re-implement that branch on purpose.
        if url.startswith("file://"):
            with open(urlparse(url).path, "r") as f:
                data = f.read()
        else:
            data = requests.get(url, timeout=5).text
        return render_template("admin_result.html", title=f"Verify {url}", output=data[:20000])
    except Exception as e:
        return render_template("admin_result.html", title="Verify failed", output=str(e))


# VULN #41 — eval() admin calculator (RCE).
@app.route("/admin/calc")
@require_login
def admin_calc():
    expr = request.args.get("expr", "1+1")
    try:
        out = str(eval(expr))  # noqa: S307
    except Exception as e:
        out = str(e)
    return render_template("admin_result.html", title="Calc", output=out)


# VULN #42 — YAML unsafe load. Admin imports config via uploaded YAML; PyYAML's
# default Loader (or FullLoader) instantiates arbitrary tags, including
# `!!python/object/apply:os.system ["id"]`, leading to RCE.
@app.route("/admin/import-config", methods=["GET", "POST"])
@require_login
def admin_import():
    output = None
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            try:
                cfg = yaml.load(f.read(), Loader=yaml.FullLoader)
                output = repr(cfg)[:5000]
            except Exception as e:
                output = f"error: {e}"
    return render_template("admin_import.html", output=output)


# VULN #43 — Debug data dump leaks secrets, env, session cookie content.
@app.route("/debug")
def debug():
    return jsonify({
        "secret_key": SECRET_KEY,
        "jwt_key": JWT_KEY,
        "admin_backdoor": ADMIN_BACKDOOR,
        "env": dict(os.environ),
        "cwd": os.getcwd(),
        "session": dict(session),
        "cookies": dict(request.cookies),
    })


# VULN #44 — Trigger an unhandled exception → Werkzeug interactive debugger console (RCE via web)
# is reachable on Flask `app.debug=True`. Visit /boom?x=. The debugger PIN is the gate;
# /debug above leaks all the inputs needed to compute it.
@app.route("/boom")
def boom():
    return 1 / int(request.args.get("x", "0"))


# VULN #45 — Open redirect.
@app.route("/redirect")
def redirect_route():
    return redirect(request.args.get("url", "/"))


# VULN #46 — Reflected XSS via search (q rendered with |safe in template).
@app.route("/search")
@require_login
def search():
    q = request.args.get("q", "")
    db = get_db()
    # VULN: SQLi via LIKE concat
    rows = db.execute(
        f"SELECT * FROM transactions WHERE memo LIKE '%{q}%' LIMIT 50"
    ).fetchall() if q else []
    return render_template("search.html", q=q, rows=rows)


# ----------------- Error handler -----------------

@app.errorhandler(500)
def err500(e):
    # VULN #47 — verbose stack trace returned. (Flask debug mode also serves the
    # Werkzeug debugger, see /boom.)
    import traceback
    return f"<pre>{traceback.format_exc()}</pre>", 500


if __name__ == "__main__":
    print("SwiftBank (VULNERABLE DEMO) running at http://127.0.0.1:5001")
    print("WARNING: This app is intentionally insecure. Do not deploy.")
    # threaded=True is required for the race-condition demo on /transfer.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5001")), threaded=True)
