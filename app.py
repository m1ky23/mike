"""
Simple login system
  1. Identification   - unique username (+ per-user ID)
  2. Authentication   - password + TOTP 2FA (Google/Microsoft Authenticator, Authy...)
  3. Authorization    - role based access (admin / user)
  4. Password storage - per-user random SALT + server-side secret PEPPER + scrypt

Run:
  export PEPPER="$(python -c 'import secrets;print(secrets.token_hex(32))')"
  export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
  python app.py
"""
import base64
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import time
from functools import wraps

import pyotp
import qrcode
import qrcode.image.svg
from flask import (Flask, abort, flash, g, redirect, render_template_string,
                   request, session, url_for)

DB_PATH = os.environ.get("DB_PATH", "/tmp/users.db" if os.environ.get("VERCEL") else "users.db")
ISSUER = "SimpleLogin"
MAX_FAILS = 5            # failed attempts before lockout
LOCK_SECONDS = 300       # lockout duration
PENDING_TTL = 300        # seconds allowed between password step and 2FA step

# The PEPPER is a secret kept OUTSIDE the database (env var / secrets manager).
# If the DB leaks, the attacker still lacks the pepper.
PEPPER = os.environ.get("PEPPER", "").encode()
if not PEPPER:
    raise SystemExit("Set the PEPPER environment variable (see top of file).")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # SESSION_COOKIE_SECURE=True,   # enable when served over HTTPS
)

# --------------------------------------------------------------------------
# Password hashing: salt + pepper
# --------------------------------------------------------------------------
def hash_password(password: str, salt: bytes) -> str:
    # Pepper step: HMAC the password with the secret pepper (fixed-length output,
    # so very long passwords can't be used for DoS either).
    peppered = hmac.new(PEPPER, password.encode(), hashlib.sha256).digest()
    # Salt + slow KDF step: unique salt per user defeats rainbow tables.
    dk = hashlib.scrypt(peppered, salt=salt, n=2**14, r=8, p=1, dklen=32)
    return dk.hex()


def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    candidate = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, stored_hash)   # constant-time compare


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
                salt          TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret   TEXT NOT NULL,
                totp_enabled  INTEGER NOT NULL DEFAULT 0,
                last_totp_step INTEGER NOT NULL DEFAULT 0,
                role          TEXT NOT NULL DEFAULT 'user',
                failed_count  INTEGER NOT NULL DEFAULT 0,
                locked_until  REAL NOT NULL DEFAULT 0
            )""")


# --------------------------------------------------------------------------
# CSRF protection (simple synchronizer token)
# --------------------------------------------------------------------------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Bad CSRF token")


app.jinja_env.globals["csrf_token"] = csrf_token


# --------------------------------------------------------------------------
# Auth helpers & role-based access control
# --------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        g.user = user
        return view(*a, **kw)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*a, **kw):
            if g.user["role"] not in roles:
                abort(403)
            return view(*a, **kw)
        return wrapped
    return decorator


def qr_svg_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


def register_failure(user):
    fails = user["failed_count"] + 1
    locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
    db().execute("UPDATE users SET failed_count=?, locked_until=? WHERE id=?",
                 (0 if locked else fails, locked, user["id"]))
    db().commit()


def is_locked(user):
    return user["locked_until"] > time.time()


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------
BASE = """
<!doctype html><title>{{ title }}</title>
<meta name=viewport content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;background:#f4f5f7;display:grid;place-items:center;min-height:100vh;margin:0}
 main{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 12px #0002;width:min(380px,92vw)}
 input,button{width:100%;padding:.65rem;margin:.35rem 0;box-sizing:border-box;font-size:1rem}
 button{background:#2457d6;color:#fff;border:0;border-radius:6px;cursor:pointer}
 .err{color:#b00020}.ok{color:#117a3d} code{word-break:break-all}
 nav a{margin-right:.8rem}
</style>
<main>
<h2>{{ title }}</h2>
{% for cat,msg in get_flashed_messages(with_categories=true) %}<p class="{{cat}}">{{msg}}</p>{% endfor %}
{{ body|safe }}
</main>
"""


def page(title, body_tpl, **ctx):
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(BASE, title=title, body=body)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 32) or not username.replace("_", "").isalnum():
            flash("Username: 3-32 chars, letters/digits/underscore.", "err")
        elif len(password) < 10:
            flash("Password must be at least 10 characters.", "err")
        else:
            salt = secrets.token_bytes(16)                       # unique salt per user
            pw_hash = hash_password(password, salt)
            totp_secret = pyotp.random_base32()
            try:
                db().execute(
                    "INSERT INTO users(username,salt,password_hash,totp_secret,role)"
                    " VALUES(?,?,?,?, 'user')",                  # always 'user'; admins are promoted separately
                    (username, salt.hex(), pw_hash, totp_secret))
                db().commit()
            except sqlite3.IntegrityError:
                flash("That username is taken.", "err")
            else:
                session.clear()
                session["enroll_user"] = username
                return redirect(url_for("enroll_2fa"))
    return page("Register", """
      <form method=post>
        <input type=hidden name=csrf value="{{ csrf_token() }}">
        <input name=username placeholder=Username required autocomplete=username>
        <input name=password type=password placeholder="Password (min 10 chars)" required autocomplete=new-password>
        <button>Create account</button>
      </form><p><a href="{{ url_for('login') }}">Back to login</a></p>""")


@app.route("/enroll-2fa", methods=["GET", "POST"])
def enroll_2fa():
    """Show the QR code once, and enable 2FA only after a valid first code."""
    username = session.get("enroll_user")
    if not username:
        return redirect(url_for("login"))
    user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    totp = pyotp.TOTP(user["totp_secret"])
    if request.method == "POST":
        if totp.verify(request.form.get("code", "").strip(), valid_window=1):
            db().execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["id"],))
            db().commit()
            session.clear()
            flash("2FA enabled. You can log in now.", "ok")
            return redirect(url_for("login"))
        flash("Invalid code, try again.", "err")
    uri = totp.provisioning_uri(name=user["username"], issuer_name=ISSUER)
    return page("Set up 2FA", """
      <p>Scan with an authenticator app, then enter the 6-digit code.</p>
      <img src="{{ qr }}" alt="QR" style="width:100%">
      <p>Or enter manually: <code>{{ secret }}</code></p>
      <form method=post>
        <input type=hidden name=csrf value="{{ csrf_token() }}">
        <input name=code inputmode=numeric pattern="[0-9]{6}" maxlength=6 placeholder="123456" required autofocus>
        <button>Verify &amp; enable</button>
      </form>""", qr=qr_svg_data_uri(uri), secret=user["totp_secret"])


@app.route("/login", methods=["GET", "POST"])
def login():
    """Step 1: identification + password."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if user and is_locked(user):
            flash("Account temporarily locked. Try again later.", "err")
        elif user and user["totp_enabled"] and verify_password(password, user["salt"], user["password_hash"]):
            session.clear()
            session["pending_user"] = user["id"]
            session["pending_at"] = time.time()
            return redirect(url_for("verify_2fa"))
        else:
            if user:
                register_failure(user)
            else:
                # Burn comparable CPU time so response timing doesn't reveal valid usernames.
                hash_password(password, b"\0" * 16)
            flash("Invalid credentials.", "err")   # generic message: no user enumeration
    return page("Login", """
      <form method=post>
        <input type=hidden name=csrf value="{{ csrf_token() }}">
        <input name=username placeholder=Username required autocomplete=username>
        <input name=password type=password placeholder=Password required autocomplete=current-password>
        <button>Continue</button>
      </form><p><a href="{{ url_for('register') }}">Create account</a></p>""")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Step 2: TOTP code. Session only becomes 'logged in' after this succeeds."""
    uid = session.get("pending_user")
    if not uid or time.time() - session.get("pending_at", 0) > PENDING_TTL:
        session.clear()
        return redirect(url_for("login"))
    user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if request.method == "POST":
        if is_locked(user):
            flash("Account temporarily locked.", "err")
            return redirect(url_for("login"))
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(user["totp_secret"])
        now_step = int(time.time() // 30)
        # valid_window=1 tolerates small clock drift; last_totp_step blocks code replay
        if totp.verify(code, valid_window=1) and now_step > user["last_totp_step"]:
            db().execute("UPDATE users SET failed_count=0, last_totp_step=? WHERE id=?",
                         (now_step, uid))
            db().commit()
            session.clear()                      # new session after privilege change
            session["user_id"] = uid
            csrf_token()
            return redirect(url_for("dashboard"))
        register_failure(user)
        flash("Invalid or reused code.", "err")
    return page("Two-factor code", """
      <form method=post>
        <input type=hidden name=csrf value="{{ csrf_token() }}">
        <input name=code inputmode=numeric pattern="[0-9]{6}" maxlength=6 placeholder="6-digit code" required autofocus>
        <button>Verify</button>
      </form>""")


@app.route("/dashboard")
@login_required
def dashboard():
    return page("Dashboard", """
      <p>Hello <b>{{ u['username'] }}</b> (ID {{ u['id'] }}) &mdash; role: <b>{{ u['role'] }}</b></p>
      <nav><a href="{{ url_for('profile') }}">Profile</a>
      {% if u['role']=='admin' %}<a href="{{ url_for('admin_panel') }}">Admin</a>{% endif %}</nav>
      <form method=post action="{{ url_for('logout') }}">
        <input type=hidden name=csrf value="{{ csrf_token() }}"><button>Log out</button></form>""", u=g.user)


@app.route("/profile")
@role_required("user", "admin")
def profile():
    return page("Profile", "<p>Visible to any authenticated user.</p><a href='/dashboard'>Back</a>")


@app.route("/admin")
@role_required("admin")
def admin_panel():
    users = db().execute("SELECT id,username,role FROM users ORDER BY id").fetchall()
    return page("Admin panel", """
      <p>Admins only.</p>
      <ul>{% for r in rows %}<li>#{{ r['id'] }} {{ r['username'] }} &mdash; {{ r['role'] }}</li>{% endfor %}</ul>
      <a href='/dashboard'>Back</a>""", rows=users)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(_):
    return page("403 Forbidden", "<p>You don't have permission to view this page.</p>"), 403


init_db()   # create tables on import (needed on Vercel, where __main__ never runs)


# --------------------------------------------------------------------------
# CLI helper: promote a user to admin (roles are never self-assignable)
#   python app.py make-admin <username>
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "make-admin":
        with sqlite3.connect(DB_PATH) as c:
            n = c.execute("UPDATE users SET role='admin' WHERE username=?", (sys.argv[2],)).rowcount
        print("Promoted." if n else "User not found.")
    else:
        app.run(debug=False)
