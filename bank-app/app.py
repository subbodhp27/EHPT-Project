from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
import json
import requests
from datetime import datetime

app = Flask(__name__)
app.secret_key = "nexabank_secret_123"

DB_PATH = "nexabank.db"
DASHBOARD_URL = "http://127.0.0.1:8000/api/log-attack"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, password TEXT, name TEXT,
        email TEXT, balance REAL DEFAULT 50000.0, account_no TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user TEXT, to_user TEXT, amount REAL,
        note TEXT, timestamp TEXT, status TEXT DEFAULT 'completed')""")
    c.execute("""CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, comment TEXT, timestamp TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, ip_address TEXT, success INTEGER, timestamp TEXT)""")
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            ("admin","admin123","Rahul Sharma","rahul@nexabank.com",482350.00,"NXB001234"),
            ("john","john@456","John Doe","john@nexabank.com",125000.00,"NXB005678"),
            ("priya","priya@789","Priya Patel","priya@nexabank.com",98500.00,"NXB009012"),
        ]
        c.executemany("INSERT INTO users (username,password,name,email,balance,account_no) VALUES (?,?,?,?,?,?)", users)
    c.execute("SELECT COUNT(*) FROM transactions")
    if c.fetchone()[0] == 0:
        txns = [
            ("admin","amazon.in",2499,"Shopping","2026-03-03 14:30:00","completed"),
            ("admin","swiggy",540,"Food order","2026-03-02 20:45:00","completed"),
            ("tcs","admin",85000,"Salary Credit","2026-03-01 09:00:00","completed"),
        ]
        c.executemany("INSERT INTO transactions (from_user,to_user,amount,note,timestamp,status) VALUES (?,?,?,?,?,?)", txns)
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_attack(attack_type, detail, severity="high", ip=None):
    entry = {
        "id": int(datetime.now().timestamp() * 1000),
        "type": attack_type,
        "detail": detail,
        "severity": severity,
        "timestamp": datetime.now().isoformat(),
        "resolved": False,
        "ip": ip or request.remote_addr
    }
    try:
        requests.post(DASHBOARD_URL, json=entry, timeout=2)
    except:
        pass
    log_file = "attack_log.json"
    logs = []
    if os.path.exists(log_file):
        with open(log_file) as f:
            try: logs = json.load(f)
            except: logs = []
    logs.insert(0, entry)
    with open(log_file, "w") as f:
        json.dump(logs[:100], f, indent=2)

SQL_PATTERNS  = ["'","--",";","OR","UNION","SELECT","DROP","1=1"]
XSS_PATTERNS  = ["<script","onerror","onload","javascript:","<img","alert("]
HTML_PATTERNS = ["<b>","</b>","<i>","</i>","<h1>","<h2>","<marquee>","<font>","<u>","</u>","<big>","<strike>"]

def detect_sqli(v): return any(p.upper() in v.upper() for p in SQL_PATTERNS)
def detect_xss(v):  return any(p.lower() in v.lower() for p in XSS_PATTERNS)
def detect_html(v): return any(p.lower() in v.lower() for p in HTML_PATTERNS)

def check_brute(username, ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT COUNT(*) FROM login_attempts
        WHERE username=? AND ip_address=? AND success=0
        AND timestamp > datetime('now','-15 minutes')""", (username, ip))
    count = c.fetchone()[0]
    conn.close()
    return count

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    sqli_detected = brute_detected = False
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        ip = request.remote_addr
        if check_brute(username, ip) >= 3:
            brute_detected = True
            log_attack("Brute Force", f"Account '{username}' — multiple failed attempts from {ip}", "high", ip)
        if detect_sqli(username) or detect_sqli(password):
            sqli_detected = True
            log_attack("SQL Injection", f"SQLi in login — username: '{username}'", "critical", ip)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            user = None; error = str(e)
        conn.close()
        conn2 = get_db()
        conn2.execute("INSERT INTO login_attempts (username,ip_address,success,timestamp) VALUES (?,?,?,?)",
            (username, ip, 1 if user else 0, datetime.now().isoformat()))
        conn2.commit(); conn2.close()
        if user:
            session["user"] = user[1]; session["name"] = user[3]
            session["balance"] = user[5]; session["account"] = user[6]
            if sqli_detected: session["attack_used"] = "SQL Injection Bypass"
            return redirect(url_for("dashboard"))
        else:
            error = error or "Invalid credentials"
    return render_template("login.html", error=error,
        sqli_detected=sqli_detected, brute_detected=brute_detected)

@app.route("/register", methods=["GET","POST"])
def register():
    xss_detected = False
    if request.method == "POST":
        name     = request.form.get("name","")
        email    = request.form.get("email","")
        username = request.form.get("username","")
        password = request.form.get("password","")
        if detect_xss(name) or detect_xss(email):
            xss_detected = True
            log_attack("Cross-Site Scripting", f"Stored XSS in registration: '{name}'", "high")
        conn = get_db()
        conn.execute("INSERT INTO users (username,password,name,email,balance,account_no) VALUES (?,?,?,?,?,?)",
            (username, password, name, email, 10000.0, f"NXB{abs(hash(username))%900000+100000}"))
        conn.commit(); conn.close()
        session["user"] = username; session["name"] = name; session["balance"] = 10000.0
        return redirect(url_for("dashboard"))
    return render_template("register.html", xss_detected=xss_detected)

@app.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect(url_for("login"))
    conn = get_db()
    txns = conn.execute("SELECT * FROM transactions WHERE from_user=? OR to_user=? ORDER BY timestamp DESC LIMIT 10",
        (session["user"], session["user"])).fetchall()
    comments = conn.execute("SELECT * FROM comments ORDER BY timestamp DESC LIMIT 5").fetchall()
    conn.close()
    return render_template("dashboard.html", user=session["user"], name=session["name"],
        balance=session.get("balance",0), account=session.get("account"),
        transactions=txns, comments=comments, attack_used=session.pop("attack_used", None))

@app.route("/search")
def search():
    if "user" not in session: return jsonify({"error":"Not logged in"}), 401
    query = request.args.get("q","")
    sqli  = detect_sqli(query)
    if sqli:
        log_attack("SQL Injection", f"SQLi in search: '{query}'", "high")
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    results   = []
    raw_query = ""
    try:
        raw_query = f"SELECT * FROM transactions WHERE note LIKE '%{query}%'"
        c.execute(raw_query)
        rows    = c.fetchall()
        results = [{"id":r[0],"from":r[1],"to":r[2],"amount":r[3],"note":r[4],"date":r[5]} for r in rows]
    except Exception as e:
        results = [{"error": str(e), "query": raw_query}]
    conn.close()
    return jsonify({"query":query,"raw_sql":raw_query,"sqli_detected":sqli,"results":results})

@app.route("/transfer", methods=["POST"])
def transfer():
    if "user" not in session: return jsonify({"error":"Not logged in"}), 401
    to_user = request.form.get("to_user","")
    amount  = float(request.form.get("amount", 0))
    note    = request.form.get("note","")
    if detect_xss(note):
        log_attack("Cross-Site Scripting", f"XSS in transfer note: '{note}'", "high")
    if detect_html(note):
        log_attack("HTML Injection", f"HTML Injection in transfer note: '{note}'", "medium")
    conn = get_db()
    conn.execute("INSERT INTO transactions (from_user,to_user,amount,note,timestamp,status) VALUES (?,?,?,?,?,?)",
        (session["user"], to_user, amount, note, datetime.now().isoformat(), "completed"))
    conn.execute("UPDATE users SET balance=balance-? WHERE username=?", (amount, session["user"]))
    conn.commit(); conn.close()
    session["balance"] = session.get("balance", 0) - amount
    return jsonify({"success": True, "message": f"₹{amount} sent to {to_user}"})

@app.route("/comment", methods=["POST"])
def comment():
    if "user" not in session: return jsonify({"error":"Not logged in"}), 401
    text = request.form.get("comment","")
    if detect_xss(text):
        log_attack("Cross-Site Scripting", f"Stored XSS in comment: '{text}'", "high")
    if detect_html(text):
        log_attack("HTML Injection", f"HTML Injection in comment: '{text}'", "medium")
    conn = get_db()
    conn.execute("INSERT INTO comments (username,comment,timestamp) VALUES (?,?,?)",
        (session["user"], text, datetime.now().isoformat()))
    conn.commit(); conn.close()
    return jsonify({"success": True})

@app.route("/profile")
def profile():
    if "user" not in session: return redirect(url_for("login"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    conn.close()
    return render_template("profile.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/api/attacks")
def api_attacks():
    if os.path.exists("attack_log.json"):
        with open("attack_log.json") as f:
            try: return jsonify(json.load(f))
            except: pass
    return jsonify([])

if __name__ == "__main__":
    init_db()
    print("NexaBank running on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)