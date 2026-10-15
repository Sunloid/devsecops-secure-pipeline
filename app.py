"""
DELIBERATELY VULNERABLE Flask app - for DevSecOps practice only.
Never deploy this anywhere public.
"""
import sqlite3
from flask import Flask, request, session, redirect, render_template, url_for

app = Flask(__name__)

# VULN (A02/A05): hardcoded secrets in source code
app.secret_key = "dev-secret-key"
DB_PASSWORD = "SuperSecret123!"   # SQLite ignores this, but we treat it like a real DB credential (Vault replaces it later)
DATABASE = "store.db"


def get_db():
    return sqlite3.connect(DATABASE)


def init_db():
    db = get_db()
    db.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        -- VULN (A02): passwords stored in plain text
        INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin');
        INSERT INTO users (username, password, role) VALUES ('alice', 'password1', 'user');
        INSERT INTO products (name, price) VALUES ('Laptop', 899.99);
        INSERT INTO products (name, price) VALUES ('Headphones', 59.50);
        INSERT INTO products (name, price) VALUES ('Keyboard', 39.00);
        INSERT INTO products (name, price) VALUES ('Monitor', 199.00);
    """)
    db.commit()
    db.close()


@app.route("/")
def index():
    return redirect(url_for("search"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN (A03 Injection): SQL built by string concatenation, no validation
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password = '" + password + "'")
        try:
            db = get_db()
            user = db.execute(query).fetchone()
            db.close()
        except Exception as e:
            # VULN (A05): leaks raw DB error to the user
            return "Database error: " + str(e), 500

        if user:
            session["user"] = user[1]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # VULN (A03 Injection): string-concatenated query
        query = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
        try:
            db = get_db()
            results = db.execute(query).fetchall()
            db.close()
        except Exception as e:
            return "Database error: " + str(e), 500
    # VULN (A03 XSS): template renders q with |safe (unescaped)
    return render_template("search.html", q=q, results=results)


if __name__ == "__main__":
    init_db()
    # VULN (A05): debug mode on and listening on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)