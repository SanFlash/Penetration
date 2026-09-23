"""
demo_target/app.py

A tiny, INTENTIONALLY VULNERABLE Flask application, built solely so the
framework in this repository has a safe, local, fully-authorized target to
demonstrate against — the same role OWASP Juice Shop / DVWA / WebGoat play
in professional training. It is not hardened, not meant for any real data,
and must never be exposed outside localhost or the sandbox it runs in.

Deliberately included weaknesses (each mirrors a chapter of the companion
training manual):
  1. Reflected XSS on GET /search?q=...            (no output encoding)
  2. Missing security headers on every response      (no CSP/HSTS/etc.)
  3. SQL Injection on GET /products?name=...         (raw string-built SQL)
  4. Broken Object-Level Authorization (IDOR) on
     GET /api/orders/<id>                            (no ownership check)
  5. A correctly-protected counterpart at
     GET /api/orders-secure/<id>                      (DOES check ownership)
     — included so the scanner's output can be verified for false positives.

Run with:  python3 demo_target/app.py
Listens on 127.0.0.1:5000 ONLY.
"""
import sqlite3
from flask import Flask, request, g, make_response, jsonify

app = Flask(__name__)
DB_PATH = "/tmp/demo_target.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS users;

        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        INSERT INTO products (name, price) VALUES
            ('Blue Widget', 9.99), ('Red Widget', 12.50), ('Green Gadget', 24.00);

        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        INSERT INTO users (username, password) VALUES
            ('alice', 'alice_pw'), ('bob', 'bob_pw');

        CREATE TABLE orders (id INTEGER PRIMARY KEY, owner TEXT, item TEXT, total REAL);
        INSERT INTO orders (owner, item, total) VALUES
            ('alice', 'Blue Widget x2', 19.98),
            ('bob', 'Green Gadget x1', 24.00);
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Weakness 1 + 2: Reflected XSS and missing security headers on every route
# ---------------------------------------------------------------------------
@app.after_request
def deliberately_weak_headers(resp):
    # No Content-Security-Policy, no X-Content-Type-Options, no HSTS.
    # This is intentional for the demo — see docstring above.
    return resp


@app.route("/")
def home():
    return """
    <h1>Demo Target — intentionally vulnerable, localhost only</h1>
    <form action="/search"><input name="q"><button>Search</button></form>
    <p><a href="/products?name=Widget">Browse products</a></p>
    <p><a href="/login">Log in</a></p>
    """


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: user input echoed straight into HTML with no encoding.
    return f"<h2>Search results</h2><p>You searched for: {q}</p>"


# ---------------------------------------------------------------------------
# Weakness 3: SQL Injection via raw string-built query
# ---------------------------------------------------------------------------
@app.route("/products")
def products():
    name = request.args.get("name", "")
    db = get_db()
    # VULNERABLE: string concatenation instead of a parameterized query.
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{name}%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Simple session-based login (for the IDOR demonstration)
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <form method="POST">
          <input name="username" placeholder="username"><br>
          <input name="password" placeholder="password" type="password"><br>
          <button>Log in</button>
        </form>
        <p>Demo accounts: alice/alice_pw, bob/bob_pw</p>
        """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    resp = make_response(jsonify({"message": f"logged in as {username}"}))
    # Deliberately simple (not production-grade) session cookie for the demo.
    resp.set_cookie("session_user", username, httponly=True)
    return resp


# ---------------------------------------------------------------------------
# Weakness 4: Broken Object-Level Authorization (IDOR)
# ---------------------------------------------------------------------------
@app.route("/api/orders/<int:order_id>")
def get_order_insecure(order_id):
    db = get_db()
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    # VULNERABLE: no check that request.cookies['session_user'] == row['owner'].
    return jsonify(dict(row))


# Correctly-protected counterpart, so the scanner's findings can be verified.
@app.route("/api/orders-secure/<int:order_id>")
def get_order_secure(order_id):
    db = get_db()
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    session_user = request.cookies.get("session_user")
    if session_user != row["owner"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(dict(row))


if __name__ == "__main__":
    init_db()
    print("Demo target initialized. Serving on http://127.0.0.1:5000 (localhost only).")
    app.run(host="127.0.0.1", port=5000, debug=False)
