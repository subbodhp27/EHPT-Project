# EHPT Project I — Attack Detection
## NexaBank + SecureShield

> A full-stack web security demonstration project built with **Python Flask + SQLite + HTML/CSS/JavaScript**

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.x + Flask |
| Database | SQLite3 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Fonts | Google Fonts (Playfair Display, Space Grotesk) |
| Communication | REST API (JSON) |

---

## 📁 Project Structure

```
EHPT-Project/
│
├── bank-app/                        # Vulnerable Banking Application
│   ├── app.py                       # Flask backend (intentionally vulnerable)
│   ├── requirements.txt             # Python dependencies
│   ├── nexabank.db                  # SQLite database (auto-created)
│   ├── attack_log.json              # Attack log file (auto-created)
│   └── templates/
│       ├── base.html                # Base layout
│       ├── index.html               # Home page
│       ├── login.html               # Login (SQL Injection vulnerable)
│       ├── register.html            # Register (XSS vulnerable)
│       ├── dashboard.html           # User dashboard
│       └── profile.html             # Profile (CSRF vulnerable)
│
├── security-dashboard/              # Attack Detection Dashboard
│   ├── app.py                       # Flask backend
│   ├── requirements.txt             # Python dependencies
│   ├── attack_log.json              # Synced attack log
│   └── templates/
│       ├── base.html                # Base layout with sidebar
│       ├── dashboard.html           # Overview page
│       ├── attacks.html             # Attack log table
│       ├── resolved.html            # Resolved incidents
│       ├── analytics.html           # Charts and stats
│       ├── threats.html             # Threat intel + prevention
│       └── rules.html               # WAF detection rules
│
└── README.md
```

---

## 🚀 How to Run

### Step 1 — Install Python dependencies

```bash
# Terminal 1 — Bank App
cd bank-app
pip install -r requirements.txt
python app.py
# Runs on http://127.0.0.1:5000

# Terminal 2 — Security Dashboard
cd security-dashboard
pip install -r requirements.txt
python app.py
# Runs on http://127.0.0.1:6000
```

### Step 2 — Open both in browser
- Bank App: http://127.0.0.1:5000
- Dashboard: http://127.0.0.1:6000

---

## 🔐 Test Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| john | john@456 | User |
| priya | priya@789 | User |

---

## 💉 Attack Demonstrations

### 1. SQL Injection
- Go to Login page
- Enter `admin'--` as username, anything as password
- Authentication bypassed via SQL Injection
- Attack auto-logged to SecureShield dashboard

### 2. Cross-Site Scripting (XSS)
- Go to Register or Dashboard
- Enter `<script>alert(document.cookie)</script>` in name/comment field
- Script stored in DB — executes for all users who view it

### 3. Brute Force
- Click "Brute Force" in Dashboard vulnerability panel
- 5 rapid failed login attempts sent
- Logged as brute force attack on dashboard

### 4. CSRF
- Go to Profile page
- Click "Simulate CSRF Attack"
- ₹50,000 transferred to attacker without CSRF token

---

## 🛡️ SecureShield Features

- Real-time attack detection and logging
- Attack classification (SQLi, XSS, Brute Force, CSRF)
- Severity levels (Critical, High, Medium, Low)
- One-click incident resolution
- WAF rules management
- Threat intelligence reference
- Analytics and charts
- IP blocking simulation
- REST API for attack ingestion

---

## 📊 Resume Bullet Points

```
• Built full-stack vulnerable web application (NexaBank) using Python Flask + SQLite
  to demonstrate OWASP Top 10 vulnerabilities including SQL Injection, XSS, CSRF, Brute Force

• Developed real-time Security Monitoring Dashboard (SecureShield) with attack detection,
  classification, alerting, and incident resolution — connected via REST API

• Tech Stack: Python, Flask, SQLite3, HTML5, CSS3, JavaScript, REST API

• Demonstrated real exploits: SQLi login bypass, Stored XSS, CSRF token bypass, Brute Force
```

---

## ⚠️ Disclaimer

This project is built **intentionally vulnerable** for educational purposes only.
Do NOT deploy to production or public servers.
For academic use — EHPT (Ethical Hacking & Penetration Testing) coursework only.
