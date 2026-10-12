"""
app.py — SecLab Training Portal (Phase 3 skeleton).

Shared safe functionality:
    /             home
    /register     create account
    /login        authenticate
    /logout       clear session
    /profile      view own account

Stub endpoints (filled in Phase 4 / Phase 5):
    /search       SQLi demo
    /comments     XSS demo
    /diagnostic   Command injection demo
    /resource     Directory traversal demo
"""

import os
import secrets
import subprocess
from functools import wraps

from flask import (
    Flask, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

import database



PORT     = 5000                                # secure/app.py uses 5001
APP_NAME = "SecLab Training Portal (vulnerable)"
SECRET_KEY = secrets.token_hex(32)

APP_DIR       = os.path.dirname(os.path.abspath(__file__))
RESOURCES_DIR = os.path.join(APP_DIR, "resources")

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

    # ---------------- CSRF token generation (enforced in Phase 5) ------
    def get_csrf_token() -> str:
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_hex(32)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    # ---------------- Auth helpers -------------------------------------
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

    # ---------------- Shared routes ------------------------------------
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

    # ---------------- Stub endpoints (Phase 4/5 will fill these) --------
       # ------------------------------------------------------------------
    # /search  — VULNERABLE: SQL Injection (Phase 4)
    #
    # The user-supplied `q` is concatenated directly into the SQL text.
    # The SQLite parser therefore treats any metacharacters the user
    # provides as SQL syntax, which is exactly what we want to show.
    #
    # Do NOT copy this pattern. The secure version uses parameters.
    # ------------------------------------------------------------------
    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        results = []
        error = None

        if q:
            db = database.get_db()
            # !!! INTENTIONALLY UNSAFE STRING CONCATENATION !!!
            sql = (
                "SELECT id, title, filename, description "
                "FROM resources "
                "WHERE title LIKE '%" + q + "%'"
            )
            try:
                results = db.execute(sql).fetchall()
            except Exception as e:
                # Show the DB error to make the injection visible in the lab.
                error = f"SQL error: {e}"

        return render_template("search.html", q=q, results=results, error=error)

    @app.route("/comments", methods=["GET", "POST"])
    @login_required
    def comments():
        if request.method == "POST":
            body = (request.form.get("body") or "").strip()
            if body:
                database.add_comment(current_user()["id"], body)
            return redirect(url_for("comments"))

        comments = database.list_comments()
        return render_template("comments.html", comments=comments)
    
       # ------------------------------------------------------------------
    # /diagnostic — VULNERABLE: OS command injection (Phase 4)
    #
    # `host` from the form is concatenated into a shell command string
    # and executed with shell=True. cmd.exe treats metacharacters such
    # as &, |, &&, || as command separators, so a payload such as:
    #
    #     127.0.0.1 & whoami
    #
    # runs a second command whose output appears in the response.
    #
    # Do NOT copy this pattern. The secure version passes an argument
    # vector to subprocess and validates `host` with an allowlist.
    # ------------------------------------------------------------------
    @app.route("/diagnostic", methods=["GET", "POST"])
    @login_required
    def diagnostic():
        host = ""
        output = ""
        error = None

        if request.method == "POST":
            host = (request.form.get("host") or "").strip()
            if host:
                # !!! INTENTIONALLY UNSAFE SHELL INVOCATION !!!
                command = "ping -n 1 " + host
                try:
                    completed = subprocess.run(
                        command,
                        shell=True,                 # <-- the dangerous part
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    output = (completed.stdout or "") + (completed.stderr or "")
                except subprocess.TimeoutExpired:
                    error = "Command timed out."
                except Exception as e:
                    error = f"Command failed: {e}"

        return render_template(
            "diagnostic.html", host=host, output=output, error=error,
        )
       # ------------------------------------------------------------------
    # /resource — VULNERABLE: directory traversal (Phase 4)
    #
    # `file` from the query string is joined to RESOURCES_DIR with no
    # normalization or containment check. The OS resolves `..` and
    # absolute paths, so a payload such as:
    #
    #     ?file=../database/schema.sql
    #
    # reads a file one directory above the intended view directory.
    #
    # Do NOT copy this pattern. The secure version restricts `file`
    # to a basename, resolves the final path with realpath, checks
    # it is inside RESOURCES_DIR, and only serves filenames already
    # registered in the resources table.
    # ------------------------------------------------------------------
    @app.route("/resource")
    @login_required
    def resource():
        filename = request.args.get("file", "")
        content = None
        error = None

        if filename:
            # !!! INTENTIONALLY UNSAFE PATH JOIN !!!
            path = os.path.join(RESOURCES_DIR, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except FileNotFoundError:
                error = f"File not found: {filename}"
            except IsADirectoryError:
                error = f"Is a directory: {filename}"
            except Exception as e:
                error = f"Error reading file: {e}"

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
    # ---------------- Errors -------------------------------------------
    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404,
                               message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(_):
        return render_template("error.html", code=500,
                               message="Something went wrong."), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)