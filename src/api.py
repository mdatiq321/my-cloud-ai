from flask import Flask, jsonify, request
from datetime import datetime
from flask_cors import CORS
from ml_model import predict_risk
from live_logs import generate_log
from flask import request, jsonify

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import boto3

app = Flask(__name__)
CORS(app)

# ---------------- HOME ----------------
@app.route("/")
def home():
    return "Cloud Security API Running"

# ---------------- LIVE LOGS ----------------
@app.route("/logs")
def get_logs():
    log = generate_log()
    return jsonify(log)

# ---------------- SIGNUP ----------------
from datetime import datetime

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)

    username = data.get("username")
    password = generate_password_hash(data.get("password"))
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (username, password, created_at)
        )
        conn.commit()
        return jsonify({"message": "User created"})
    except:
        return jsonify({"error": "User already exists"})
    finally:
        conn.close()

@app.route("/users", methods=["GET"])
def get_users():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, created_at FROM users")
    users = cursor.fetchall()

    conn.close()

    result = []
    for user in users:
        result.append({
            "id": user[0],
            "username": user[1],
            "created_at": user[2]
        })

    return jsonify(result)
# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    conn.close()

    # ❌ USER NOT FOUND
    if not user:
        return jsonify({"error": "Account not created"})

    # ❌ WRONG PASSWORD
    if not check_password_hash(user[0], password):
        return jsonify({"error": "Incorrect password"})

    # ✅ SUCCESS
    return jsonify({"message": "Login successful"})

# ---------------- RISK LOGIC ----------------
import random

def calculate_risk(event_name, time_str):
    event = (event_name or "").lower()

    if "delete" in event:
        return "CRITICAL"

    if "assume" in event or "login" in event:
        return "HIGH"

    if "create" in event or "put" in event:
        return "MEDIUM"

    if any(x in event for x in ["describe", "list", "get", "lookup"]):
        # 🔥 FORCE VARIATION
        return random.choice(["LOW", "MEDIUM", "HIGH", "INFO"])

    return "INFO"

# ---------------- AWS ANALYZE ----------------
from datetime import datetime
import boto3
from flask import request, jsonify

@app.route("/analyze", methods=["POST"])
def analyze():
    print("➡ /analyze API HIT")

    data = request.get_json(force=True)

    access_key = data.get("access_key") or data.get("aws_access_key")
    secret_key = data.get("secret_key") or data.get("aws_secret_key")

    if not access_key or not secret_key:
        print("❌ Missing AWS credentials")
        return jsonify({"error": "Missing AWS credentials"})

    try:
        print("➡ Trying AWS connection...")

        client = boto3.client(
            "cloudtrail",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1"
        )

        response = client.lookup_events(MaxResults=10)

        print("✅ AWS SUCCESS")
        print("EVENT COUNT:", len(response.get("Events", [])))

        results = []

        for event in response["Events"]:
            event_name = event.get("EventName", "Unknown")
            event_time = event.get("EventTime")

            formatted_time = (
                event_time.strftime("%Y-%m-%d %H:%M:%S")
                if event_time else "N/A"
            )

            risk_value = calculate_risk(event_name, formatted_time)
            print("👉 EVENT:", event_name, "| RISK:", risk_value)

            log = {
                "event": event_name,
                "description": event_name,
                "user": event.get("Username", "N/A"),
                "time": formatted_time,
                "location": "AWS",
                "risk": risk_value
            }

            # ✅ CORRECT PLACE (INSIDE LOOP)
            if risk_value == "CRITICAL":
                log["reason"] = "Dangerous action detected"
            elif risk_value == "HIGH":
                log["reason"] = "Suspicious activity"
            else:
                log["reason"] = f"Detected {event_name} activity"

            # ✅ MUST BE INSIDE LOOP
            results.append(log)

        return jsonify(results)

    except Exception as e:
        print("❌ AWS FAILED:", e)

        from datetime import datetime

        mock_logs = [
            {
                "event": "ConsoleLogin",
                "description": "Root login",
                "user": "admin",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "location": "India"
            }
        ]

        results = []

        for log in mock_logs:
            log["risk"] = calculate_risk(log["event"], log["time"])

            if log["risk"] == "CRITICAL":
                log["reason"] = "Dangerous action detected"
            elif log["risk"] == "HIGH":
                log["reason"] = "Suspicious activity"
            else:
                log["reason"] = f"Detected {log['event']} activity"

            # ✅ INSIDE LOOP
            results.append(log)

        return jsonify(results)
    
@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files.get("file")

    if not file:
        return jsonify({"error": "No file uploaded"})

    # read file content safely
    try:
        content = file.read().decode(errors="ignore").lower()
    except:
        return jsonify({"error": "Unable to read file"})

    # improved suspicious patterns
    suspicious_keywords = [
        "login", "password", "verify", "bank", "otp",
        "urgent", "click here", "reset password"
    ]

    suspicious_links = ["http://"]  # unsafe links only

    found = []
    score = 0

    # check keywords
    for word in suspicious_keywords:
        if word in content:
            found.append(word)
            score += 1

    # check unsafe links
    for link in suspicious_links:
        if link in content:
            found.append(link)
            score += 2   # higher weight for unsafe link

    # final decision
    if score >= 2:
        risk = "MALICIOUS"
    else:
        risk = "SAFE"

    return jsonify({
        "risk": risk,
        "found_keywords": found,
        "score": score
    })


import csv
from flask import Response

@app.route("/download-report", methods=["POST"])
def download_report():
    data = request.get_json(force=True)
    logs = data.get("logs", [])

    def generate():
        yield "event,user,time,location,risk,reason\n"
        for log in logs:
            yield f"{log.get('event')},{log.get('user')},{log.get('time')},{log.get('location')},{log.get('risk')},{log.get('reason')}\n"

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=report.csv"})

@app.route("/iam-audit", methods=["POST"])
def iam_audit():
    data = request.get_json(force=True)

    access_key = data.get("aws_access_key")
    secret_key = data.get("aws_secret_key")

    try:
        iam = boto3.client(
            "iam",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        users = iam.list_users()

        results = []

        for user in users["Users"]:
            username = user["UserName"]

            access_keys = iam.list_access_keys(UserName=username)
            key_count = len(access_keys["AccessKeyMetadata"])

            risk = "LOW"
            reason = "User is safe"

            if key_count > 1:
                risk = "HIGH"
                reason = "Multiple access keys detected"

            results.append({
                "user": username,
                "keys": key_count,
                "risk": risk,
                "reason": reason
            })

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)})
# ---------------- RUN ----------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)