from flask import Flask, request, jsonify, send_from_directory
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import logging
import warnings
from urllib3.exceptions import InsecureRequestWarning
import os
import threading
import time
from datetime import datetime, timedelta
import base64

warnings.simplefilter('ignore', InsecureRequestWarning)

app = Flask(__name__, static_folder='.')
app.logger.setLevel(logging.INFO)

# ========================= CONFIGURATION =========================
ACCOUNTS_FILE                = "accounts.txt"
TOKEN_API_URL                = "https://rizerxguestaccountacceee.vercel.app//rizer"
TOKEN_REFRESH_INTERVAL_HOURS = 2
MAX_LOG_LINES                = 1000
PORT                         = 31208          # change to 31221 if you want old port
DEBUG_MODE                   = False

# ======================== GLOBAL STATE ===========================
_token_store      = []
_token_store_lock = threading.Lock()
_last_refresh_time = None
_next_refresh_time = None
_checking_mode = False
_checking_lock = threading.Lock()

_log_lines      = []
_log_lines_lock = threading.Lock()
_log_counter    = 0

_scheduler_started = False
_scheduler_lock    = threading.Lock()

# Version cache (still used for headers)
_versions_cache = {
    "ob_version": "OB53",
    "client_version": "1.123.2",
    "last_fetch": 0
}

# ======================== HELPER FUNCTIONS ========================
def mask(s, show=4):
    s = str(s)
    if len(s) <= show * 2:
        return s[:2] + "***" + s[-2:]
    return s[:show] + "***" + s[-show:]

def _push_log(msg: str):
    global _log_counter
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with _log_lines_lock:
        _log_counter += 1
        _log_lines.append({"id": _log_counter, "msg": line})
        if len(_log_lines) > MAX_LOG_LINES:
            del _log_lines[:len(_log_lines) - MAX_LOG_LINES]

def get_versions():
    global _versions_cache
    now = time.time()
    if now - _versions_cache["last_fetch"] > 3600:
        try:
            resp = requests.get(
                "https://raw.githubusercontent.com/dangerapix/danger-ffjwt/main/versions.json",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                _versions_cache["ob_version"] = data.get("ob_version", "OB53")
                _versions_cache["client_version"] = data.get("client_version", "1.123.2")
                _versions_cache["last_fetch"] = now
        except Exception:
            pass
    return _versions_cache["ob_version"], _versions_cache["client_version"]

def load_accounts_from_file():
    accounts = []
    try:
        if not os.path.exists(ACCOUNTS_FILE):
            _push_log(f"[ERROR] {ACCOUNTS_FILE} not found!")
            return accounts
        with open(ACCOUNTS_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    _push_log(f"[WARN] Line {line_num}: invalid format, skipping.")
                    continue
                uid, pw = line.split(":", 1)
                accounts.append({"uid": uid.strip(), "password": pw.strip()})
        _push_log(f"[INFO] Loaded {len(accounts)} account(s) from {ACCOUNTS_FILE}")
    except Exception as e:
        _push_log(f"[ERROR] Loading accounts: {e}")
    return accounts

# ======================== TOKEN FETCHER (EXTERNAL API) ============
def fetch_token_from_api(uid, password, idx, total):
    _push_log(f"[{idx}/{total}] >>> UID: {mask(uid)}  PASS: {mask(password)}")
    for attempt in range(1, 4):
        try:
            resp = requests.get(
                TOKEN_API_URL,
                params={"uid": uid, "password": password},
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success":
                acc_uid = str(data.get("account_uid") or data.get("uid", ""))
                jwt = data.get("jwt_token", "")
                region = data.get("region", "")
                if acc_uid and jwt and region:
                    _push_log(f"[{idx}/{total}] ✓ SUCCESS | UID: {mask(acc_uid)} | REGION: {region}")
                    return {"uid": acc_uid, "token": jwt, "region": region}
                else:
                    _push_log(f"[{idx}/{total}] [WARN] Incomplete response fields.")
            else:
                _push_log(f"[{idx}/{total}] [FAIL] API status={data.get('status')} | attempt {attempt}/3")
        except requests.exceptions.RequestException as e:
            _push_log(f"[{idx}/{total}] [ERROR] Network error attempt {attempt}/3: {e}")
            if attempt < 3:
                time.sleep(2 * attempt)
        except Exception as e:
            _push_log(f"[{idx}/{total}] [ERROR] Unexpected: {e}")
            break
    _push_log(f"[{idx}/{total}] ✗ FAILED — UID: {mask(uid)}")
    return None

# ======================== TOKEN REFRESH & VERIFICATION ============
def _verify_existing_tokens(tokens):
    alive = 0
    for t in tokens[:5]:
        try:
            parts = t.get("token", "").split(".")
            if len(parts) < 2:
                continue
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.b64decode(padded))
            if payload.get("exp", 0) > time.time() + 300:
                alive += 1
        except Exception:
            pass
    if alive:
        _push_log(f"[VERIFY] {alive} token(s) still valid.")
    return alive > 0

def refresh_all_tokens(is_verify=False):
    global _last_refresh_time, _next_refresh_time, _checking_mode
    label = "VERIFY" if is_verify else "REFRESH"
    _push_log("")
    _push_log("╔══════════════════════════════════════╗")
    _push_log(f"  TOKEN {label} STARTED")
    _push_log("╚══════════════════════════════════════╝")
    accounts = load_accounts_from_file()
    if not accounts:
        _push_log("[WARN] No accounts found. Aborting.")
        with _checking_lock:
            _checking_mode = False
        return
    _push_log(f"[INFO] Processing {len(accounts)} accounts...")
    _push_log("─────────────────────────────────────────")
    successful, failed = [], 0
    total = len(accounts)
    for idx, acc in enumerate(accounts, 1):
        result = fetch_token_from_api(acc["uid"], acc["password"], idx, total)
        if result:
            successful.append(result)
        else:
            failed += 1
        time.sleep(0.3)
    with _token_store_lock:
        uid_map = {t["uid"]: t for t in _token_store}
        for t in successful:
            uid_map[t["uid"]] = t
        _token_store.clear()
        _token_store.extend(uid_map.values())
    _last_refresh_time = datetime.now()
    _next_refresh_time = _last_refresh_time + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)
    _push_log("─────────────────────────────────────────")
    _push_log(f"[DONE] SUCCESS: {len(successful)}  |  FAILED: {failed}")
    _push_log(f"[INFO] TOKENS IN MEMORY: {len(_token_store)}")
    _push_log(f"[INFO] NEXT REFRESH: {_next_refresh_time.strftime('%Y-%m-%d %H:%M:%S')}")
    _push_log("╔══════════════════════════════════════╗")
    _push_log(f"  {label} COMPLETE")
    _push_log("╚══════════════════════════════════════╝")
    _push_log("")
    with _checking_lock:
        _checking_mode = False
    if failed and not successful:
        _push_log("[WARN] All tokens failed! Will retry next cycle.")
    elif failed:
        _push_log(f"[WARN] {failed} failed, {len(successful)} active — service OK.")

# ======================== BACKGROUND SCHEDULER ====================
def _scheduler_loop():
    global _checking_mode, _last_refresh_time, _next_refresh_time
    _push_log("[SYSTEM] ══════════════════════════════════")
    _push_log("[SYSTEM]   FREE FIRE LIKE SERVICE STARTED")
    _push_log("[SYSTEM] ══════════════════════════════════")
    _push_log("[SYSTEM] Initial token generation...")
    refresh_all_tokens()
    while True:
        total_sleep = TOKEN_REFRESH_INTERVAL_HOURS * 3600
        for _ in range(total_sleep):
            time.sleep(1)
        with _checking_lock:
            _checking_mode = True
        _push_log("")
        _push_log("[!] ══ CHECKING TOKEN ══ Like service paused ══")
        with _token_store_lock:
            existing = list(_token_store)
        if _verify_existing_tokens(existing):
            _push_log("[VERIFY] ✓ Tokens still valid! Service resumed.")
            _last_refresh_time = datetime.now()
            _next_refresh_time = _last_refresh_time + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)
            with _checking_lock:
                _checking_mode = False
        else:
            _push_log("[VERIFY] ✗ Tokens expired! Generating new tokens...")
            refresh_all_tokens(is_verify=True)

def start_scheduler():
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
    t = threading.Thread(target=_scheduler_loop, daemon=True, name="TokenScheduler")
    t.start()
    _push_log("[SYSTEM] Token scheduler thread started.")

def get_tokens_from_memory(server_name):
    with _token_store_lock:
        region_tokens = [t for t in _token_store if t.get("region") == server_name]
        if not region_tokens:
            region_tokens = list(_token_store)
    return region_tokens if region_tokens else None

# ======================== CORE PROTOBUF & ENCRYPTION ==============
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')
    except Exception as e:
        _push_log(f"[ERROR] Encryption failed: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        msg = like_pb2.like()
        msg.uid = int(user_id)
        msg.region = region
        return msg.SerializeToString()
    except Exception as e:
        _push_log(f"[ERROR] Like protobuf failed: {e}")
        return None

def create_protobuf(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except Exception as e:
        _push_log(f"[ERROR] UID protobuf failed: {e}")
        return None

def enc(uid):
    pb = create_protobuf(uid)
    return encrypt_message(pb) if pb else None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        _push_log(f"[ERROR] Decode failed: {e}")
        return None

def make_request(encrypt_hex, server_name, token, extra_tokens=None):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    ob_ver, client_ver = get_versions()
    tokens_to_try = [token]
    if extra_tokens:
        tokens_to_try += [t["token"] for t in extra_tokens[1:4]]
    for idx, tok in enumerate(tokens_to_try):
        try:
            edata = bytes.fromhex(encrypt_hex)
            headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip",
                'Authorization': f"Bearer {tok}",
                'Content-Type': "application/x-www-form-urlencoded",
                'Expect': "100-continue",
                'X-Unity-Version': client_ver,
                'X-GA': "v1 1",
                'ReleaseVersion': ob_ver
            }
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
            if response.status_code != 200:
                _push_log(f"[WARN] make_request attempt {idx+1}: HTTP {response.status_code}")
                continue
            binary = response.content
            if not binary:
                _push_log(f"[WARN] make_request attempt {idx+1}: empty response")
                continue
            decoded = decode_protobuf(binary)
            if decoded is not None:
                return decoded
        except Exception as e:
            _push_log(f"[ERROR] make_request attempt {idx+1}: {e}")
    _push_log("[ERROR] make_request: all attempts exhausted")
    return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        ob_ver, client_ver = get_versions()
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': client_ver,
            'X-GA': "v1 1",
            'ReleaseVersion': ob_ver
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return response.status if response.status != 200 else await response.text()
    except Exception as e:
        _push_log(f"[ERROR] send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        pb = create_protobuf_message(uid, server_name)
        if not pb:
            return None
        encrypted_uid = encrypt_message(pb)
        if not encrypted_uid:
            return None
        tokens = get_tokens_from_memory(server_name)
        if not tokens:
            _push_log("[ERROR] No tokens for like requests")
            return None
        tasks = [send_request(encrypted_uid, tokens[i % len(tokens)]["token"], url) for i in range(100)]
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        _push_log(f"[ERROR] send_multiple_requests: {e}")
        return None

# ======================== FLASK ENDPOINTS =========================
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/terminal')
def terminal():
    return send_from_directory('.', 'terminal.html')

@app.route('/logs/poll')
def log_poll():
    try:
        after = int(request.args.get('after', 0))
    except (ValueError, TypeError):
        after = 0
    with _log_lines_lock:
        new_lines = [l for l in _log_lines if l["id"] > after]
    return jsonify({"lines": new_lines, "last_id": new_lines[-1]["id"] if new_lines else after})

@app.route('/logs/all')
def log_all():
    with _log_lines_lock:
        all_lines = list(_log_lines)
    return jsonify({"lines": all_lines})

@app.route('/token_status')
def token_status():
    with _token_store_lock:
        tokens = list(_token_store)
    with _checking_lock:
        checking = _checking_mode
    return jsonify({
        "total_tokens": len(tokens),
        "checking_mode": checking,
        "last_refresh": _last_refresh_time.strftime('%Y-%m-%d %H:%M:%S') if _last_refresh_time else "Not yet",
        "next_refresh": _next_refresh_time.strftime('%Y-%m-%d %H:%M:%S') if _next_refresh_time else "Pending",
        "next_refresh_ts": int(_next_refresh_time.timestamp()) if _next_refresh_time else 0,
        "tokens": [{"uid": mask(t["uid"]), "region": t.get("region", "?")} for t in tokens]
    })

@app.route('/like', methods=['GET'])
def handle_requests():
    with _checking_lock:
        if _checking_mode:
            return jsonify({"error": "CHECKING TOKEN — Verification in progress. Try again shortly."}), 503
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400
    try:
        tokens = get_tokens_from_memory(server_name)
        if not tokens:
            return jsonify({"error": "No tokens available. Please wait for token generation."}), 503
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "UID encryption failed."}), 500
        before = make_request(encrypted_uid, server_name, token, extra_tokens=tokens)
        if before is None:
            return jsonify({"error": "Failed to get player info. Check UID/server_name."}), 500
        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))
        if server_name == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"
        await_result = asyncio.run(send_multiple_requests(uid, server_name, like_url))
        if await_result is None:
            _push_log("[WARN] Like requests may have failed, but continuing...")
        after = make_request(encrypted_uid, server_name, token, extra_tokens=tokens)
        if after is None:
            return jsonify({"error": "Failed to get player info after likes."}), 500
        data_after = json.loads(MessageToJson(after))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        like_given = after_like - before_like
        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": 1 if like_given != 0 else 2
        })
    except Exception as e:
        _push_log(f"[ERROR] Like endpoint: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    start_scheduler()
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE, threaded=True)