"""
app.py — SecLab Training Portal (secure build).

Security status by endpoint:

    /             home                                safe
    /register     create account                      safe
    /login        authenticate                        safe
    /logout       clear session                       safe
    /profile      view own account                    safe
    /search       parameterized query (Phase 5.1)     safe
    /comments     output encoding + CSP (Phase 5.2)   safe
    /diagnostic   allowlist + arg vector (Phase 5.3)  safe
    /resource     stub — Phase 5.4 will implement     pending

The two app files (vulnerable/, secure/) diverge only in the four
vulnerable endpoints. Everything else is identical, so that the
security difference is isolated and visible.
"""

import os
import re
import secrets
import subprocess
from functools import wraps

from flask import (
    Flask, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

import database


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT       = 5001
APP_NAME   = "SecLab Training Portal (secure)"
SECRET_KEY = secrets.token_hex(32)

APP_DIR       = os.path.dirname(os.path.abspath(__file__))
RESOURCES_DIR = os.path.join(APP_DIR, "resources")


# ---------------------------------------------------------------------------
# Validation patterns for /diagnostic — allowlist, not blocklist.
# ---------------------------------------------------------------------------
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=SECRET_KEY,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=64 * 1024,
    )

    database.init_db()
    app.teardown_appcontext(database.close_db)

    # -----------------------------------------------------------------
    # Response hardening (Phase 5.2 — defense in depth for XSS)
    # -----------------------------------------------------------------
    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # -----------------------------------------------------------------
    # CSRF token generation
    # -----------------------------------------------------------------
    def get_csrf_token() -> str:
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_hex(32)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    # -----------------------------------------------------------------
    # Auth helpers
    # -----------------------------------------------------------------
    def current_user():
        uid = session.get("user_id")
        return database.get_user_by_id(uid) if uid is not None else None

    app.jinja_env.globals["current_user"] = current_user

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_user() is None:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    # -----------------------------------------------------------------
    # Shared routes — identical to the vulnerable build
    # -----------------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            bio      = (request.form.get("bio") or "").strip()

            if not (3 <= len(username) <= 32) or not username.isalnum():
                error = "Username must be 3–32 alphanumeric characters."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            elif database.get_user_by_username(username) is not None:
                error = "That username is already taken."
            else:
                database.create_user(
                    username, generate_password_hash(password), bio[:500],
                )
                return redirect(url_for("login", registered="1"))

        return render_template("register.html", error=error)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            user = database.get_user_by_username(username)
            if user is None or not check_password_hash(user["password_hash"], password):
                error = "Invalid username or password."
            else:
                session.clear()
                session["user_id"] = user["id"]
                nxt = request.args.get("next") or url_for("profile")
                if not nxt.startswith("/"):
                    nxt = url_for("profile")
                return redirect(nxt)

        return render_template(
            "login.html",
            error=error,
            registered=request.args.get("registered"),
        )

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user=current_user())

    # -----------------------------------------------------------------
    # /search — SECURE: parameterized query (Phase 5.1)
    # -----------------------------------------------------------------
    @app.route("/search")
    def search():
        q = (request.args.get("q") or "").strip()
        results = []
        error = None

        if len(q) > 200:
            error = "Query too long."
        elif q:
            db = database.get_db()
            try:
                results = db.execute(
                    "SELECT id, title, filename, description "
                    "FROM resources "
                    "WHERE title LIKE ?",
                    (f"%{q}%",),
                ).fetchall()
            except Exception:
                error = "Search failed."

        return render_template("search.html", q=q, results=results, error=error)

    # -----------------------------------------------------------------
    # /comments — SECURE: output encoding (Phase 5.2)
    # -----------------------------------------------------------------
    @app.route("/comments", methods=["GET", "POST"])
    @login_required
    def comments():
        if request.method == "POST":
            body = (request.form.get("body") or "").strip()
            if body:
                if len(body) > 1000:
                    body = body[:1000]
                database.add_comment(current_user()["id"], body)
            return redirect(url_for("comments"))

        comments = database.list_comments()
        return render_template("comments.html", comments=comments)

    # -----------------------------------------------------------------
    # /diagnostic — SECURE: allowlist + argument vector (Phase 5.3)
    #
    # Three layers:
    #   1. Allowlist validation of `host` (IPv4 or hostname regex).
    #      Metacharacters fail the match and nothing runs.
    #   2. subprocess.run with an argument list and shell=False — no
    #      shell to interpret `&`, `|`, `&&`, backticks, etc.
    #   3. Only a fixed success/failure message is returned; the
    #      subprocess stdout/stderr is never reflected to the client.
    # -----------------------------------------------------------------
    @app.route("/diagnostic", methods=["GET", "POST"])
    @login_required
    def diagnostic():
        host = ""
        result = None
        error = None

        if request.method == "POST":
            host = (request.form.get("host") or "").strip()

            if not host:
                error = "Please enter a hostname or IP address."
            elif len(host) > 253:
                error = "Host name is too long."
            elif not (IPV4_RE.match(host) or HOSTNAME_RE.match(host)):
                error = "Invalid hostname or IP address."
            else:
                try:
                    completed = subprocess.run(
                        ["ping", "-n", "1", host],
                        shell=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    result = (
                        f"Host {host} is reachable."
                        if completed.returncode == 0
                        else f"Host {host} did not respond."
                    )
                except subprocess.TimeoutExpired:
                    result = f"Host {host} did not respond (timeout)."
                except Exception:
                    error = "Diagnostic failed."

        return render_template(
            "diagnostic.html", host=host, result=result, error=error,
        )

    # -----------------------------------------------------------------
    # /resource — SECURE: implemented in Phase 5.4
    # -----------------------------------------------------------------
  
      # -----------------------------------------------------------------
    # /resource — SECURE: basename + DB allowlist + realpath (Phase 5.4)
    #
    # Three layers:
    #   1. Filename must equal its own basename — no separators, no ..,
    #      no absolute paths, no drive letters.
    #   2. Filename must be registered in the resources table — the
    #      database is the allowlist.
    #   3. The realpath of the final file must still live inside
    #      RESOURCES_DIR (catches symlinks, covers future regressions).
    #
    # Any failure returns a generic "Resource not found." message.
    # No file is opened, and no path is echoed back to the client.
    # -----------------------------------------------------------------
    @app.route("/resource")
    @login_required
    def resource():
        filename = request.args.get("file", "")
        content = None
        error = None

        if filename:
            # Layer 1 — syntactic basename check.
            if os.path.basename(filename) != filename:
                error = "Resource not found."

            else:
                # Layer 2 — the resources table is the allowlist.
                db = database.get_db()
                row = db.execute(
                    "SELECT title FROM resources WHERE filename = ?",
                    (filename,),
                ).fetchone()

                if row is None:
                    error = "Resource not found."

                else:
                    # Layer 3 — canonicalize and confirm containment.
                    resources_real = os.path.realpath(RESOURCES_DIR)
                    path = os.path.realpath(
                        os.path.join(RESOURCES_DIR, filename)
                    )
                    if os.path.commonpath([path, resources_real]) != resources_real:
                        error = "Resource not found."
                    else:
                        try:
                            with open(path, "r", encoding="utf-8") as f:
                                content = f.read()
                        except FileNotFoundError:
                            error = "Resource not found."
                        except Exception:
                            error = "Could not read resource."

        # Catalogue shown alongside the viewer.
        db = database.get_db()
        catalogue = db.execute(
            "SELECT title, filename, description FROM resources ORDER BY title"
        ).fetchall()

        return render_template(
            "resource.html",
            filename=filename,
            content=content,
            error=error,
            catalogue=catalogue,
        )

    # -----------------------------------------------------------------
    # Error handlers — never leak tracebacks to the client
    # -----------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404,
                               message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(_):
        return render_template("error.html", code=500,
                               message="Something went wrong."), 500

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
app = create_app()


if __name__ == "__main__":
    # debug=False is mandatory: this app binds to 0.0.0.0 and is
    # reachable from the private link. debug=True would expose the
    # Werkzeug interactive console to every host that can reach it.
    app.run(host="0.0.0.0", port=PORT, debug=False)