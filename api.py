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
# API database target: income-point-7ddf3 (Firebase project supplied for this update).
DB_URL = os.environ.get("DB_URL", "https://income-point-7ddf3-default-rtdb.firebaseio.com").rstrip("/")
DB_SECRET = os.environ.get("DB_SECRET", "UFR7TWmxoXYPU06AEgDNRnxc3adNUK41Y4neUrRQ")
app.secret_key = os.environ.get("SESSION_SECRET", "_CCwRwHrD9yL4W34Jx6CF29Vdt0dAN-fiE-Zhp3m06eP1qD4vlNlkbQ-lEaCHarN")
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


def db_change_balance(uid, delta):
    """Atomically change a user's balance using Firebase ETag compare-and-swap."""
    if not DB_SECRET:
        raise RuntimeError("DB_SECRET is not configured")
    url = f"{DB_URL}/users/{requests.utils.quote(str(uid), safe='')}/balance.json"
    for _ in range(8):
        response = requests.get(url, params={"auth": DB_SECRET}, headers={"X-Firebase-ETag": "true"}, timeout=(5, 15))
        response.raise_for_status()
        etag = response.headers.get("ETag")
        current = response.json()
        current = float(current or 0)
        updated = round(current + float(delta), 2)
        if updated < 0:
            return None
        write = requests.put(url, params={"auth": DB_SECRET}, json=updated,
                             headers={"if-match": etag or "null", "Content-Type": "application/json"},
                             timeout=(5, 15))
        if write.status_code == 412:
            continue
        write.raise_for_status()
        return updated
    raise RuntimeError("Balance update conflict; please retry")

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
    settings_raw = db_request("admin", "GET") or {}
    settings = {k: v for k, v in settings_raw.items() if k not in {"users", "gmailSettings", "referralChallenges"}}
    if isinstance(settings_raw.get("gmailSettings"), dict):
        settings["gmailSettings"] = {k: v for k, v in settings_raw["gmailSettings"].items() if k != "password"}
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
    g_settings = db_request("admin/gmailSettings", "GET") or {}
    public_gmail_settings = {k: v for k, v in g_settings.items() if k not in {"password", "adminToken", "secret"}}
    return jsonify({
        "submissions": subs,
        "settings": public_gmail_settings
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

@app.route('/api/deposit', methods=['POST'])
@login_required
def deposit():
    d = request.get_json(silent=True) or {}
    uid = current_uid()
    try:
        amount = round(float(d.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount"}), 400
    method = str(d.get("method", "")).strip()
    trx_id = str(d.get("trxId", "")).strip()
    screenshot = d.get("screenshotData", "")
    settings = db_request("admin", "GET") or {}
    minimum = float(settings.get("minDepositAmount", 50) or 50)
    if amount < minimum or amount > 100000:
        return jsonify({"success": False, "message": f"Deposit must be between {minimum} and 100000"}), 400
    if method not in {"Bkash", "Nagad"} or len(trx_id) < 5 or len(trx_id) > 100:
        return jsonify({"success": False, "message": "Enter a valid payment method and transaction ID"}), 400
    if not isinstance(screenshot, str) or not screenshot.startswith("data:image/") or len(screenshot) > 1000000:
        return jsonify({"success": False, "message": "Upload a valid screenshot smaller than 700 KB"}), 400
    if not re.match(r"^data:image/(png|jpeg|jpg|webp);base64,", screenshot, re.I):
        return jsonify({"success": False, "message": "Unsupported screenshot format"}), 400
    transactions = db_request("transactions", "GET") or {}
    if any(isinstance(t, dict) and t.get("trxId") == trx_id for t in transactions.values()):
        return jsonify({"success": False, "message": "This transaction ID has already been submitted"}), 409
    item = {
        "userId": uid, "type": "Deposit", "amount": amount,
        "details": f"{method} deposit", "method": method, "trxId": trx_id,
        "screenshotData": screenshot, "date": datetime.now().isoformat(),
        "status": "pending"
    }
    db_request("transactions", "POST", item)
    return jsonify({"success": True, "message": "Deposit submitted for admin review"})

@app.route('/api/history', methods=['GET'])
@login_required
def history():
    uid = current_uid()
    all_trx = db_request("transactions", "GET")
    my_trx = []
    if all_trx:
        for v in all_trx.values():
            if isinstance(v, dict) and v.get('userId') == uid:
                safe_item = dict(v)
                safe_item.pop("screenshotData", None)
                my_trx.append(safe_item)
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
    d = request.get_json(silent=True) or {}
    uid = current_uid()
    plan_name = str(d.get('planName', '')).strip()
    plans = db_request("plans", "GET") or {}
    plan = next((p for p in plans.values() if isinstance(p, dict) and p.get("name") == plan_name), None)
    if not plan:
        return jsonify({"success": False, "message": "Plan not found"}), 404
    amount = float(plan.get("price", 0) or 0)
    if amount <= 0:
        return jsonify({"success": False, "message": "Plan price is invalid"}), 400
    user = db_request(f"users/{uid}", "GET") or {}
    if user.get("premiumPlan") and user.get("activePlanUntil"):
        try:
            if datetime.fromisoformat(user["activePlanUntil"]) > datetime.now():
                return jsonify({"success": False, "message": "An earning plan is already active"}), 409
        except (ValueError, TypeError):
            pass
    new_balance = db_change_balance(uid, -amount)
    if new_balance is None:
        return jsonify({"success": False, "message": "Insufficient wallet balance. Deposit funds first."}), 400
    duration = max(int(plan.get("durationDays", 1) or 1), 1)
    from datetime import timedelta
    expiry = (datetime.now() + timedelta(days=duration)).isoformat()
    db_request(f"users/{uid}/premiumPlan", "PUT", plan_name)
    db_request(f"users/{uid}/activePlanUntil", "PUT", expiry)
    db_request(f"users/{uid}/lastClaimDate", "PUT", "")
    plan_snapshot = {
        "name": plan_name,
        "price": amount,
        "dailyIncome": float(plan.get("dailyIncome", 0) or 0),
        "durationDays": duration,
        "purchasedAt": datetime.now().isoformat()
    }
    db_request(f"users/{uid}/activePlanDetails", "PUT", plan_snapshot)
    db_request(f"users/{uid}/planDaysClaimed", "PUT", 0)
    trx = {
        "userId": uid, "type": "Plan Purchase", "amount": -amount,
        "details": f"Plan: {plan_name}", "date": datetime.now().isoformat(),
        "status": "approved"
    }
    db_request("transactions", "POST", trx)
    return jsonify({"success": True, "newBalance": new_balance, "expiresAt": expiry})

@app.route('/api/submit_task', methods=['POST'])
@login_required
def submit_task():
    d = request.get_json(silent=True) or {}
    uid = current_uid()
    task_id = str(d.get("taskId", "")).strip()
    category = str(d.get("category", "basic")).strip()
    screenshot = d.get("screenshotData", "")
    if category not in {"basic", "telegram"} or not task_id:
        return jsonify({"success": False, "message": "Invalid task"}), 400
    if not isinstance(screenshot, str) or not screenshot.startswith("data:image/") or len(screenshot) > 1000000:
        return jsonify({"success": False, "message": "Upload a valid screenshot smaller than 700 KB"}), 400
    if not re.match(r"^data:image/(png|jpeg|jpg|webp);base64,", screenshot, re.I):
        return jsonify({"success": False, "message": "Unsupported screenshot format"}), 400
    tasks = db_request(f"tasks/{category}", "GET") or {}
    task = tasks.get(task_id)
    if not isinstance(task, dict):
        return jsonify({"success": False, "message": "Task not found"}), 404
    try:
        reward = float(task.get("reward", 0) or 0)
    except (TypeError, ValueError):
        reward = 0
    if reward <= 0:
        return jsonify({"success": False, "message": "Task reward is not configured"}), 400
    submissions = db_request("taskSubmissions", "GET") or {}
    for old in submissions.values():
        if isinstance(old, dict) and old.get("userId") == uid and old.get("taskId") == task_id and old.get("category") == category and old.get("status") in {"pending", "processing", "approved"}:
            return jsonify({"success": False, "message": "You have already submitted this task"}), 409
    submission = {
        "userId": uid, "taskId": task_id, "category": category,
        "taskName": task.get("name") or task.get("title") or "Task",
        "reward": reward, "screenshotData": screenshot,
        "date": datetime.now().isoformat(), "status": "pending"
    }
    db_request("taskSubmissions", "POST", submission)
    return jsonify({"success": True, "message": "Screenshot submitted for admin review"})

@app.route('/api/complete_task', methods=['POST'])
@login_required
def complete_task():
    return jsonify({"success": False, "message": "Task screenshots must be submitted for admin review"}), 410

@app.route('/api/claim_daily', methods=['POST'])
@login_required
def claim_daily():
    uid = current_uid()
    user = db_request(f"users/{uid}", "GET") or {}
    plan = user.get("activePlanDetails") or {}
    if not user.get("premiumPlan") or not plan:
        return jsonify({"success": False, "message": "No active earning plan"}), 400
    try:
        duration = max(int(plan.get("durationDays", 0) or 0), 1)
        amount = float(plan.get("dailyIncome", 0) or 0)
        claimed_days = int(user.get("planDaysClaimed", 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Plan reward configuration is invalid"}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Daily reward is not configured"}), 400
    expires_at = user.get("activePlanUntil")
    if not expires_at:
        return jsonify({"success": False, "message": "Plan expiry is missing"}), 400
    try:
        if datetime.fromisoformat(expires_at) <= datetime.now():
            return jsonify({"success": False, "message": "Your earning plan has expired"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Plan expiry data is invalid"}), 400
    if claimed_days >= duration:
        return jsonify({"success": False, "message": "All daily rewards for this plan have been claimed"}), 400
    today = datetime.now().strftime("%Y-%m-%d")
    if user.get("lastClaimDate") == today:
        return jsonify({"success": False, "message": "Already claimed today"}), 409
    new_balance = float(user.get("balance", 0) or 0) + amount
    db_request(f"users/{uid}/balance", "PUT", new_balance)
    db_request(f"users/{uid}/lastClaimDate", "PUT", today)
    db_request(f"users/{uid}/planDaysClaimed", "PUT", claimed_days + 1)
    db_request("transactions", "POST", {
        "userId": uid, "type": "Daily Plan Reward", "amount": amount,
        "details": f"{plan.get('name', 'Plan')} · Day {claimed_days + 1}/{duration}",
        "date": datetime.now().isoformat(), "status": "approved"
    })
    return jsonify({"success": True, "amount": amount, "daysClaimed": claimed_days + 1, "remainingDays": duration - claimed_days - 1, "newBalance": new_balance})

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


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "ok": True,
        "databaseConfigured": bool(DB_URL and DB_SECRET),
        "sessionConfigured": bool(app.secret_key)
    })


# ---- INCOME-POINT earning workflows ----
def _valid_uid(uid):
    return isinstance(uid, str) and 8 <= len(uid) <= 128 and re.match(r'^[A-Za-z0-9_-]+$', uid)

@app.route('/api/earning/account-listing', methods=['POST'])
def earning_account_listing():
    d=request.get_json(silent=True) or {}
    uid=d.get('uid'); platform=str(d.get('platform','')).strip().title()
    contact=str(d.get('contact','')).strip()
    profile=str(d.get('profileUrl','')).strip()
    proof=str(d.get('proof','')).strip()
    if not _valid_uid(uid) or platform not in ('Facebook','Instagram') or not contact or len(contact)>180 or not profile.startswith(('https://','http://')) or not proof or len(proof)>1000:
        return jsonify(success=False,message='Please provide valid listing details.'),400
    if any(x in (contact+' '+proof).lower() for x in ('password','2fa code','cookie','recovery phrase','private key')):
        return jsonify(success=False,message='Do not submit passwords, 2FA codes, cookies or recovery secrets.'),400
    item={'userId':uid,'platform':platform,'contact':contact,'profileUrl':profile,'ownershipProof':proof,'status':'pending','createdAt':datetime.now().isoformat()}
    db_request('accountListings','POST',item)
    return jsonify(success=True,message='Listing submitted for admin review.')

@app.route('/api/earning/create-job', methods=['POST'])
def earning_create_job():
    d=request.get_json(silent=True) or {}
    uid=d.get('uid'); title=str(d.get('title','')).strip(); desc=str(d.get('description','')).strip()
    try: reward=float(d.get('reward')); slots=int(d.get('slots'))
    except (TypeError,ValueError): return jsonify(success=False,message='Invalid reward or worker count.'),400
    if not _valid_uid(uid) or not title or len(title)>100 or not desc or len(desc)>2000 or reward<=0 or slots<1 or slots>500:
        return jsonify(success=False,message='Please complete all job details.'),400
    user=db_request(f'users/{uid}','GET') or {}
    settings=db_request('admin','GET') or {}
    post_fee=float(settings.get('jobPostFee',0) or 0)
    required=reward*slots+post_fee
    balance=float(user.get('balance',0) or 0)
    if balance<required: return jsonify(success=False,message=f'Insufficient wallet balance. Required ৳{required:.2f}.'),400
    # Reserve the full job budget until the job is completed/cancelled.
    db_request(f'users/{uid}/balance','PUT',round(balance-required,2))
    job={'ownerId':uid,'title':title,'description':desc,'reward':reward,'slots':slots,'remainingSlots':slots,'reservedBudget':reward*slots,'postFee':post_fee,'status':'pending','kind':'user_job','createdAt':datetime.now().isoformat()}
    db_request('userJobs','POST',job)
    db_request('transactions','POST',{'userId':uid,'type':'Job Budget Reserved','amount':-required,'status':'approved','date':datetime.now().isoformat(),'details':title})
    return jsonify(success=True,message='Job submitted. It will appear in Micro Jobs after admin approval.')

@app.route('/api/earning/submit-work', methods=['POST'])
def earning_submit_work():
    d=request.get_json(silent=True) or {}
    uid=d.get('uid'); task_id=str(d.get('taskId','')).strip(); proof=str(d.get('proof','')).strip()
    if not _valid_uid(uid) or not task_id or len(proof)<2 or len(proof)>5000:
        return jsonify(success=False,message='Invalid submission.'),400
    task=db_request(f'tasks/{task_id}','GET')
    if not task or task.get('status')!='approved' or task.get('enabled') is False:
        return jsonify(success=False,message='This task is not available.'),404
    existing=db_request('workSubmissions','GET') or {}
    count=sum(1 for x in existing.values() if x.get('taskId')==task_id and x.get('userId')==uid)
    if count>=int(task.get('perUserLimit',1) or 1):
        return jsonify(success=False,message='You have reached the task limit.'),409
    job_task=bool(task.get('jobId'))
    item={'taskId':task_id,'userId':uid,'ownerId':task.get('ownerId'),'proof':proof,'status':'pending_owner' if job_task else 'pending','reward':float(task.get('reward',0) or 0),'createdAt':datetime.now().isoformat()}
    db_request('workSubmissions','POST',item)
    return jsonify(success=True,message='Work submitted for review.')

@app.route('/api/earning/review-job-submission', methods=['POST'])
def earning_review_job_submission():
    d=request.get_json(silent=True) or {}
    owner=d.get('uid'); submission_id=str(d.get('submissionId','')); decision=d.get('decision')
    if not _valid_uid(owner) or not submission_id or decision not in ('approve','reject'):
        return jsonify(success=False,message='Invalid review request.'),400
    sub=db_request(f'workSubmissions/{submission_id}','GET') or {}
    if sub.get('ownerId')!=owner or sub.get('status')!='pending_owner':
        return jsonify(success=False,message='You are not allowed to review this submission.'),403
    if decision=='approve':
        user=db_request(f"users/{sub['userId']}",'GET') or {}
        db_request(f"users/{sub['userId']}/balance",'PUT',round(float(user.get('balance',0) or 0)+float(sub.get('reward',0) or 0),2))
        db_request('transactions','POST',{'userId':sub['userId'],'type':'User Job Reward','amount':float(sub.get('reward',0) or 0),'status':'approved','date':datetime.now().isoformat(),'details':sub.get('taskId')})
    db_request(f'workSubmissions/{submission_id}/status','PUT','approved' if decision=='approve' else 'rejected')
    db_request(f'workSubmissions/{submission_id}/reviewedAt','PUT',datetime.now().isoformat())
    return jsonify(success=True,message='Submission reviewed.')

@app.route('/api/earning/my-jobs', methods=['GET'])
def earning_my_jobs():
    uid=request.args.get('uid','')
    if not _valid_uid(uid): return jsonify(success=False,message='Invalid user.'),400
    jobs=db_request('userJobs','GET') or {}
    subs=db_request('workSubmissions','GET') or {}
    mine=[{'id':k,**v} for k,v in jobs.items() if v.get('ownerId')==uid]
    reviews=[{'id':k,**v} for k,v in subs.items() if v.get('ownerId')==uid and v.get('status')=='pending_owner']
    return jsonify(jobs=mine,pendingReviews=reviews)

@app.route('/api/earning/submit-typing', methods=['POST'])
def earning_submit_typing():
    d=request.get_json(silent=True) or {}
    d['proof']=d.get('typedText','')
    return earning_submit_work_internal(d,'typing')

def earning_submit_work_internal(d,kind):
    uid=d.get('uid'); task_id=str(d.get('taskId','')).strip(); proof=str(d.get('proof','')).strip()
    if not _valid_uid(uid) or not task_id or not proof or len(proof)>10000:
        return jsonify(success=False,message='Invalid typing submission.'),400
    task=db_request(f'tasks/{task_id}','GET') or {}
    if task.get('kind')!=kind or task.get('status')!='approved' or task.get('enabled') is False:
        return jsonify(success=False,message='This task is unavailable.'),404
    existing=db_request('workSubmissions','GET') or {}
    count=sum(1 for x in existing.values() if x.get('taskId')==task_id and x.get('userId')==uid)
    if count>=int(task.get('perUserLimit',1) or 1): return jsonify(success=False,message='Task limit reached.'),409
    db_request('workSubmissions','POST',{'taskId':task_id,'userId':uid,'proof':proof,'status':'pending','reward':float(task.get('reward',0) or 0),'createdAt':datetime.now().isoformat()})
    return jsonify(success=True,message='Typing work submitted for review.'),200

