from flask import Flask, render_template, request, jsonify
import json, os
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "attack_log.json"

def load_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            try: return json.load(f)
            except: return []
    return []

def save_logs(logs):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def get_stats(logs):
    total    = len(logs)
    active   = sum(1 for l in logs if not l.get("resolved"))
    resolved = sum(1 for l in logs if l.get("resolved"))
    critical = sum(1 for l in logs if l.get("severity") == "critical")
    types = {}
    ips   = {}
    for l in logs:
        t  = l.get("type",  "Other");   types[t]  = types.get(t, 0)  + 1
        ip = l.get("ip",    "unknown"); ips[ip]   = ips.get(ip, 0)   + 1
    return {
        "total":    total,
        "active":   active,
        "resolved": resolved,
        "critical": critical,
        "by_type":  types,
        "by_ip":    dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5])
    }

def match_id(log_id, attack_id):
    try: return int(float(str(log_id))) == int(float(str(attack_id)))
    except: return str(log_id) == str(attack_id)

@app.route("/")
def home():
    logs  = load_logs()
    return render_template("dashboard.html", logs=logs[:20], stats=get_stats(logs))

@app.route("/attacks")
def attacks():
    logs  = load_logs()
    ft = request.args.get("type",   "all")
    fs = request.args.get("status", "all")
    filtered = logs
    if ft != "all": filtered = [l for l in filtered if ft.lower() in l.get("type","").lower()]
    if fs == "active":     filtered = [l for l in filtered if not l.get("resolved")]
    elif fs == "resolved": filtered = [l for l in filtered if l.get("resolved")]
    return render_template("attacks.html", logs=filtered, stats=get_stats(logs), filter_type=ft, filter_status=fs)

@app.route("/resolved")
def resolved():
    logs = load_logs()
    return render_template("resolved.html", logs=[l for l in logs if l.get("resolved")], stats=get_stats(logs))

@app.route("/analytics")
def analytics():
    logs   = load_logs()
    hourly = {}
    for l in logs:
        try:
            h = datetime.fromisoformat(l["timestamp"]).strftime("%H:00")
            hourly[h] = hourly.get(h, 0) + 1
        except: pass
    return render_template("analytics.html", logs=logs, stats=get_stats(logs), hourly=json.dumps(hourly))

@app.route("/threats")
def threats():
    logs = load_logs()
    return render_template("threats.html", stats=get_stats(logs))

@app.route("/rules")
def rules():
    logs = load_logs()
    return render_template("rules.html", stats=get_stats(logs))

@app.route("/api/log-attack", methods=["POST"])
def log_attack():
    data = request.get_json()
    if not data: return jsonify({"error": "No data"}), 400
    logs  = load_logs()
    entry = {
        "id":        int(datetime.now().timestamp() * 1000),
        "type":      data.get("type",      "Unknown"),
        "detail":    data.get("detail",    ""),
        "severity":  data.get("severity",  "medium"),
        "timestamp": data.get("timestamp", datetime.now().isoformat()),
        "ip":        data.get("ip",        "unknown"),
        "resolved":  False
    }
    logs.insert(0, entry)
    save_logs(logs[:200])
    return jsonify({"success": True, "entry": entry})

@app.route("/api/resolve/<attack_id>", methods=["POST"])
def resolve_attack(attack_id):
    logs  = load_logs()
    found = False
    for l in logs:
        if match_id(l.get("id"), attack_id):
            l["resolved"]    = True
            l["resolved_at"] = datetime.now().isoformat()
            found = True
            break
    save_logs(logs)
    return jsonify({"success": found})

@app.route("/api/resolve-all", methods=["POST"])
def resolve_all():
    logs = load_logs()
    for l in logs:
        l["resolved"]    = True
        l["resolved_at"] = datetime.now().isoformat()
    save_logs(logs)
    return jsonify({"success": True})

@app.route("/api/logs")
def api_logs():
    return jsonify(load_logs())

@app.route("/api/clear", methods=["POST"])
def clear_logs():
    save_logs([])
    return jsonify({"success": True})

if __name__ == "__main__":
    print("\n=== SecureShield on http://127.0.0.1:8000 ===\n")
    app.run(debug=True, port=8000)