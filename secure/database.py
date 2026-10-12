"""
database.py — SQLite helpers for the SecLab Training Portal.

Phase 3: identical in the vulnerable and secure versions.
Contains only parameterized queries and Werkzeug hashing.

Design:
- One connection per request, stored on Flask's `g`.
- Row factory = sqlite3.Row so templates can use column names.
- PRAGMA foreign_keys enabled per connection (SQLite defaults off).
"""

import os
import sqlite3

from flask import g
from werkzeug.security import generate_password_hash


APP_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(APP_DIR, "lab.db")
SCHEMA_PATH = os.path.join(os.path.dirname(APP_DIR), "database", "schema.sql")


# ----------------------------------------------------------------------
# Per-request connection
# ----------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ----------------------------------------------------------------------
# Initialization + seed
# ----------------------------------------------------------------------
def init_db() -> None:
    first_time = not os.path.exists(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    if conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0:
        _seed(conn)

    conn.commit()
    conn.close()

    print(f"[db] {'created' if first_time else 'using'} {DB_PATH}")


def _seed(conn: sqlite3.Connection) -> None:
    demo_users = [
        ("alice", "password123", "Security engineer in training."),
        ("bob",   "hunter2",     "Just here for the coffee."),
    ]
    user_ids = {}
    for username, password, bio in demo_users:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, bio) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), bio),
        )
        user_ids[username] = cur.lastrowid

    conn.execute(
        "INSERT INTO comments (user_id, body) VALUES (?, ?)",
        (user_ids["alice"], "Welcome to the training portal!"),
    )
    conn.execute(
        "INSERT INTO comments (user_id, body) VALUES (?, ?)",
        (user_ids["bob"], "Remember: never trust user input."),
    )

    resources = [
        ("Introduction",      "intro.md",         "Start here."),
        ("SQL notes",         "sql-notes.md",     "Notes on SQL injection."),
        ("XSS notes",         "xss-notes.md",     "Notes on cross-site scripting."),
        ("Command injection", "command-notes.md", "Notes on OS command injection."),
    ]
    conn.executemany(
        "INSERT INTO resources (title, filename, description) VALUES (?, ?, ?)",
        resources,
    )


# ----------------------------------------------------------------------
# Query helpers (safe — parameterized)
# ----------------------------------------------------------------------
def get_user_by_username(username: str):
    return get_db().execute(
        "SELECT id, username, password_hash, bio FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(user_id: int):
    return get_db().execute(
        "SELECT id, username, password_hash, bio FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def create_user(username: str, password_hash: str, bio: str = "") -> int:
    db = get_db()
    cur = db.execute(
        "INSERT INTO users (username, password_hash, bio) VALUES (?, ?, ?)",
        (username, password_hash, bio),
    )
    db.commit()
    return cur.lastrowid


def list_comments():
    return get_db().execute(
        """
        SELECT c.id, c.body, c.created_at, u.username
        FROM comments AS c
        JOIN users    AS u ON u.id = c.user_id
        ORDER BY c.created_at DESC, c.id DESC
        """
    ).fetchall()


def add_comment(user_id: int, body: str) -> int:
    db = get_db()
    cur = db.execute(
        "INSERT INTO comments (user_id, body) VALUES (?, ?)",
        (user_id, body),
    )
    db.commit()
    return cur.lastrowid