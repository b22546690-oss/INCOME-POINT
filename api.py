from flask import Flask, request, jsonify, session
import os
import requests
import json
import time
import re
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Production configuration: set DB_URL, DB_SECRET and SESSION_SECRET in Vercel.
# The selected database is cash-5355f (the first database identified in the project).
DB_URL = os.environ.get("DB_URL", "https://free-9d3b4-default-rtdb.firebaseio.com").rstrip("/")
DB_SECRET = os.environ.get("DB_SECRET", "FwOUpZowVYHJmRZOGefTQAszzoccpsGg3YhuTu0O")
app.secret_key = os.environ.get("SESSION_SECRET")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not app.secret_key:
            return jsonify({"success": False, "message": "Server session security is not configured"}), 503
        uid = session.get("uid")
        if not uid:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        supplied_uid = request.args.get("uid")
        if request.is_json and isinstance(request.get_json(silent=True), dict):
            supplied_uid = request.get_json(silent=True).get("uid", supplied_uid)
        if supplied_uid and supplied_uid != uid:
            return jsonify({"success": False, "message": "Forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapped

def current_uid():
    return session.get("uid")


def db_request(path, method="GET", data=None):
    if not DB_SECRET:
        raise RuntimeError("DB_SECRET is not configured")
    safe_path = "/".join(requests.utils.quote(part, safe="") for part in str(path).strip("/").split("/"))
    url = f"{DB_URL}/{safe_path}.json"
    headers = {"Content-Type": "application/json"}
    try:
        r = requests.request(
            method.upper(), url,
            params={"auth": DB_SECRET},
            json=data if method.upper() in {"POST", "PUT", "PATCH"} else None,
            headers=headers,
            timeout=(5, 15),
        )
        r.raise_for_status()
        return r.json() if r.content else None
    except requests.RequestException as exc:
        app.logger.exception("Database request failed")
        raise RuntimeError("Database service unavailable") from exc


def sanitize_input(text, type="text"):
    if type == "username":
        return re.match(r'^[a-zA-Z0-9_]{5,20}$', text) is not None
    if type == "name":
        return re.match(r'^[a-zA-Z0-9\s.,:]{3,25}$', text) is not None
    return True

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json
    login_input = d.get('input', '').strip()
    password = d.get('password')
    
    users = db_request("users", "GET")
    
    found_user = None
    uid = None
    
    if users:
        for k, v in users.items():
            stored = v.get("password", "")
            password_ok = False
            if isinstance(stored, str) and stored.startswith(("pbkdf2:", "scrypt:")):
                try:
                    password_ok = check_password_hash(stored, password or "")
                except (ValueError, TypeError):
                    password_ok = False
            else:
                password_ok = bool(password) and stored == password
                if password_ok:
                    db_request(f"users/{k}/password", "PUT", generate_password_hash(password))
            if (v.get('email') == login_input or v.get('username') == login_input) and password_ok:
                found_user = v
                uid = k
                break
    
    if found_user:
        if not app.secret_key:
            return jsonify({"success": False, "message": "SESSION_SECRET is not configured"}), 503
        session.clear()
        session["uid"] = uid
        session.permanent = True
        return jsonify({"success": True, "uid": uid})
    return jsonify({"success": False, "message": "Invalid Credentials"})

@app.route('/api/register', methods=['POST'])
def register():
    d = request.json
    username = d.get('username', '').strip()
    email = d.get('email', '').strip()
    password = d.get('password')
    fullname = d.get('fullname', '').strip()
    ref_code_input = d.get('refCode', '').strip()
    
    if not app.secret_key:
        return jsonify({"success": False, "message": "SESSION_SECRET is not configured"}), 503
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return jsonify({"success": False, "message": "Password must be 8-128 characters"})
    if not sanitize_input(username, "username") or not sanitize_input(fullname, "name"):
        return jsonify({"success": False, "message": "Invalid Input Format"})

    users = db_request("users", "GET")
    if users:
        for v in users.values():
            if v.get('username') == username:
                return jsonify({"success": False, "message": "Username taken"})
            if v.get('email') == email:
                return jsonify({"success": False, "message": "Email already used"})

    referred_by_uid = None
    ref_msg = ""
    
    if ref_code_input:
        ref_codes = db_request("referralCodes", "GET")
        if ref_codes:
            for r_uid, r_code in ref_codes.items():
                if r_code == ref_code_input:
                    referred_by_uid = r_uid
                    break
        if not referred_by_uid:
            ref_msg = "Invalid Referral Code"

    import random
    import uuid
    new_ref_id = f"cash{random.randint(10000, 99999)}"
    uid = str(uuid.uuid4())
    
    new_user = {
        "username": username,
        "password": generate_password_hash(password), 
        "fullname": fullname,
        "email": email,
        "refId": new_ref_id,
        "referredBy": referred_by_uid,
        "isAccountActive": True,
        "balance": 0,
        "totalWithdraw": 0,
        "joinDate": datetime.now().isoformat(),
        "profilePictureUrl": "https://iili.io/fWs359j.jpg"
    }
    
    db_request(f"users/{uid}", "PUT", new_user)
    db_request(f"referralCodes/{uid}", "PUT", new_ref_id)
    
    if referred_by_uid:
        db_request(f"users/{referred_by_uid}/referrals/{uid}", "PUT", True)
        
    session.clear()
    session["uid"] = uid
    session.permanent = True
    return jsonify({"success": True, "uid": uid, "refMessage": ref_msg})

@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    uid = current_uid()
    if not uid: return jsonify({})
    
    user_data = db_request(f"users/{uid}", "GET")
    settings = db_request("admin", "GET")
    tasks = db_request("tasks", "GET")
    plans = db_request("plans", "GET")
    challenges = db_request("admin/referralChallenges", "GET")
    
    # Check for pending activation or plan requests
    pending_plan = False
    
    transactions = db_request("transactions", "GET")
    if transactions:
        for t in transactions.values():
            if t.get('userId') == uid and t.get('status') == 'pending':
                if t.get('type') == 'Plan Purchase':
                    pending_plan = True

    if user_data and 'password' in user_data: del user_data['password']
    
    return jsonify({
        "user": user_data,
        "settings": settings,
        "tasks": tasks,
        "plans": plans,
        "challenges": challenges,
        "pendingPlan": pending_plan
    })

@app.route('/api/gmail_page', methods=['GET'])
@login_required
def gmail_page():
    uid = current_uid()
    subs = db_request(f"users/{uid}/gmailSubmissions", "GET")
    g_settings = db_request("admin/gmailSettings", "GET")
    return jsonify({
        "submissions": subs,
        "settings": g_settings
    })

@app.route('/api/submit_gmail', methods=['POST'])
@login_required
def submit_gmail():
    d = request.json
    uid = current_uid()
    email = d.get('email')
    
    g_settings = db_request("admin/gmailSettings", "GET") or {}
    
    if g_settings.get('todayCount', 0) >= g_settings.get('globalLimit', 200):
        return jsonify({"success": False, "message": "Global Limit Reached"})
        
    submission = {
        "email": email,
        "price": g_settings.get('price', 5),
        "date": datetime.now().isoformat(),
        "status": "pending",
        "passwordUsed": g_settings.get('password')
    }
    
    db_request(f"users/{uid}/gmailSubmissions", "POST", submission)
    new_count = g_settings.get('todayCount', 0) + 1
    db_request("admin/gmailSettings/todayCount", "PUT", new_count)
    
    return jsonify({"success": True})

@app.route('/api/history', methods=['GET'])
@login_required
def history():
    uid = current_uid()
    all_trx = db_request("transactions", "GET")
    my_trx = []
    if all_trx:
        for v in all_trx.values():
            if v.get('userId') == uid:
                my_trx.append(v)
    return jsonify(my_trx)

@app.route('/api/withdraw', methods=['POST'])
@login_required
def withdraw():
    d = request.json
    uid = current_uid()
    amount = float(d.get('amount', 0) or 0)
    method = d.get('method')
    number = d.get('number')
    
    user = db_request(f"users/{uid}", "GET") or {}
    settings = db_request("admin", "GET") or {}
    
    if not user.get('isAccountActive'):
        return jsonify({"success": False, "message": "Inactive Account"})
        
    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount"})
    if (user or {}).get('balance', 0) < amount:
        return jsonify({"success": False, "message": "Low Balance"})
        
    if amount < (settings or {}).get('minWithdrawAmount', 100):
        return jsonify({"success": False, "message": "Amount too low"})
        
    trx = {
        "userId": uid,
        "type": "Withdrawal",
        "amount": -amount,
        "details": f"{method} to {number}",
        "date": datetime.now().isoformat(),
        "status": "pending"
    }
    db_request("transactions", "POST", trx)
    new_bal = user.get('balance', 0) - amount
    db_request(f"users/{uid}/balance", "PUT", new_bal)
    
    return jsonify({"success": True})

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    d = request.json
    uid = current_uid()
    fullname = d.get('fullname', '').strip()
    username = d.get('username', '').strip()
    
    if not sanitize_input(username, "username") or not sanitize_input(fullname, "name"):
        return jsonify({"success": False, "message": "Invalid Format"})
    
    db_request(f"users/{uid}/fullname", "PUT", fullname)
    db_request(f"users/{uid}/username", "PUT", username)
    return jsonify({"success": True})

@app.route('/api/activate', methods=['POST'])
@login_required
def activate():
    return jsonify({"success": False, "message": "Account activation has been discontinued"}), 410

@app.route('/api/buy_plan', methods=['POST'])
@login_required
def buy_plan():
    d = request.json
    uid = current_uid()
    plan_name = d.get('planName')
    plans = db_request("plans", "GET") or {}
    plan = next((p for p in plans.values() if p.get("name") == plan_name), None)
    if not plan:
        return jsonify({"success": False, "message": "Plan not found"}), 404
    amount = float(plan.get("price", 0) or 0)
    if amount <= 0:
        return jsonify({"success": False, "message": "Plan price is invalid"}), 400
    trx_id = d.get('trxId')
    method = d.get('method')

    transactions = db_request("transactions", "GET")
    if transactions:
        for t in transactions.values():
            if t.get('userId') == uid and t.get('type') == 'Plan Purchase' and t.get('status') == 'pending':
                return jsonify({"success": False, "message": "Request already pending"})

    trx = {
        "userId": uid,
        "type": "Plan Purchase",
        "amount": amount,
        "details": f"Plan: {plan_name}",
        "trxId": trx_id,
        "method": method,
        "date": datetime.now().isoformat(),
        "status": "pending"
    }
    db_request("transactions", "POST", trx)
    return jsonify({"success": True})

@app.route('/api/complete_task', methods=['POST'])
@login_required
def complete_task():
    d = request.json
    uid = current_uid()
    tid = d.get('taskId')
    task_catalog = db_request("tasks", "GET") or {}
    task = (task_catalog.get("basic", {}) or {}).get(tid)
    if not task:
        return jsonify({"success": False, "message": "Task not found"}), 404
    reward = float(task.get("reward", 0) or 0)
    if reward <= 0:
        return jsonify({"success": False, "message": "Task reward is invalid"}), 400

    user = db_request(f"users/{uid}", "GET") or {}
    today = datetime.now().strftime("%Y-%m-%d")
    
    if user.get('lastTaskDate') == today:
        return jsonify({"success": False, "message": "Daily limit reached"})
    
    completed = user.get('completedTasks', {})
    if tid in completed:
        return jsonify({"success": False, "message": "Already completed"})
        
    new_balance = user.get('balance', 0) + reward
    db_request(f"users/{uid}/balance", "PUT", new_balance)
    db_request(f"users/{uid}/lastTaskDate", "PUT", today)
    db_request(f"users/{uid}/completedTasks/{tid}", "PUT", True)
    
    return jsonify({"success": True, "newBalance": new_balance})

@app.route('/api/claim_daily', methods=['POST'])
@login_required
def claim_daily():
    d = request.json
    uid = current_uid()
    user = db_request(f"users/{uid}", "GET") or {}
    plans = db_request("plans", "GET") or {}
    active_plan = next((p for p in plans.values() if p.get("name") == user.get("premiumPlan")), None)
    if not active_plan:
        return jsonify({"success": False, "message": "No active earning plan"}), 400
    duration = max(int(active_plan.get("durationDays", 0) or 0), 1)
    amount = float(active_plan.get("dailyIncome", 0) or 0)
    if amount <= 0:
        amount = (float(active_plan.get("price", 0) or 0) * 1.10) / duration
    if amount <= 0:
        return jsonify({"success": False, "message": "Daily reward is not configured"}), 400
    today = datetime.now().strftime("%Y-%m-%d")
    
    if user.get('lastClaimDate') == today:
        return jsonify({"success": False, "message": "Already claimed today"})
        
    new_balance = user.get('balance', 0) + amount
    db_request(f"users/{uid}/balance", "PUT", new_balance)
    db_request(f"users/{uid}/lastClaimDate", "PUT", today)
    
    return jsonify({"success": True})

@app.route('/api/claim_ref_reward', methods=['POST'])
@login_required
def claim_ref_reward():
    d = request.json
    uid = current_uid()
    target = str(d.get('target'))
    user = db_request(f"users/{uid}", "GET") or {}
    challenges = db_request("admin/referralChallenges", "GET") or []
    tier = next((item for item in challenges if str(item.get("target")) == target), None) if isinstance(challenges, list) else None
    if not tier:
        return jsonify({"success": False, "message": "Referral reward tier not found"}), 404
    reward = float(tier.get("reward", 0) or 0)
    if reward <= 0:
        return jsonify({"success": False, "message": "Referral reward is invalid"}), 400
    
    claimed = user.get('dailyRefClaims', {})
    if claimed.get(target):
        return jsonify({"success": False, "message": "Already claimed"})
        
    new_balance = user.get('balance', 0) + reward
    db_request(f"users/{uid}/balance", "PUT", new_balance)
    db_request(f"users/{uid}/dailyRefClaims/{target}", "PUT", True)
    
    return jsonify({"success": True})
    if type == "name":
        return re.match(r'^[a-zA-Z0-9\s.,:]{3,25}$', text) is not None
    return True

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    response = jsonify({"success": True})
    response.delete_cookie("session")
    return response
