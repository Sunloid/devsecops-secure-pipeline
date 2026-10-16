"""
DELIBERATELY VULNERABLE Flask app - for DevSecOps practice only.
Never deploy this anywhere public.
"""
import sqlite3
import os 
import secrets
from flask import Flask, request, session, redirect, render_template, url_for
from flask_wtf import CSRFProtect


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
csrf = CSRFProtect(app)

# VULN (A02/A05): hardcoded secrets in source code
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
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT);
        -- VULN (A02): passwords stored in plain text
        INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin');
        INSERT INTO users (username, password, role) VALUES ('alice', 'password1', 'user');
        INSERT INTO products (name, price, category) VALUES ('Laptop', 899.99, 'Computers');
        INSERT INTO products (name, price, category) VALUES ('Monitor', 199.00, 'Computers');
        INSERT INTO products (name, price, category) VALUES ('Keyboard', 39.00, 'Accessories');
        INSERT INTO products (name, price, category) VALUES ('Mouse', 24.50, 'Accessories');
        INSERT INTO products (name, price, category) VALUES ('Headphones', 59.50, 'Audio');
        INSERT INTO products (name, price, category) VALUES ('Speaker', 79.00, 'Audio');
        INSERT INTO products (name, price, category) VALUES ('Webcam', 45.00, 'Accessories');
        INSERT INTO products (name, price, category) VALUES ('USB Hub', 19.99, 'Accessories');
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
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        try:
            db = get_db()
            user = db.execute(query, (username, password)).fetchone()
            db.close()
        except Exception as e:
            # VULN (A05): leaks raw DB error to the user
            return "Database error: " + str(e), 500

        if user:
            session["user"] = user[1]
            session["role"] = user[3]
            return redirect(url_for("dashboard"))
        error = "Wrong username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("search"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"],
                           role=session.get("role", "user"))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    catalog = []
    db = get_db()
    if q:
        # VULN (A03 Injection): string-concatenated query
        query = "SELECT name, price FROM products WHERE name LIKE ?"
        try:
            db = get_db()
            results = db.execute(query, ('%' + q + '%',)).fetchall()
        except Exception as e:
            db.close()
            return "Database error: " + str(e), 500
    else:
        catalog = db.execute("SELECT name, price, category FROM products").fetchall()
    db.close()
    # VULN (A03 XSS): template renders q with |safe (unescaped)
    return render_template("search.html", q=q, results=results, catalog=catalog)


if __name__ == "__main__":
    init_db()
    # VULN (A05): debug mode on and listening on all interfaces
    app.run(host="127.0.0.1", port=5000, debug=False)