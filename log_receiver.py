from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from collections import defaultdict
import time
import requests

app = FastAPI(title="AI-SIEM API")

# =========================================
# In-Memory Storage
# =========================================
logs = []
blocked_ips = set()

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 minutes


# =========================================
# Version Check (Deployment Test)
# =========================================
@app.get("/")
def root():
    return {"version": "AI-SIEM v2 - Firewall Enabled"}


# =========================================
# Get Real Client IP (Render Safe)
# =========================================
def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


# =========================================
# Geolocation (IP Info)
# =========================================
def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }
    except:
        return {}


# =========================================
# Brute Force Detection Logic
# =========================================
def check_bruteforce():
    now = time.time()
    fail_counter = defaultdict(int)

    for log in logs:
        if (
            log["status"] == "failed"
            and now - log["timestamp"] <= BRUTE_FORCE_WINDOW
        ):
            fail_counter[log["ip"]] += 1

    for ip, count in fail_counter.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            blocked_ips.add(ip)


# =========================================
# Receive Log
# =========================================
@app.post("/api/log")
async def receive_log(request: Request):

    ip = get_client_ip(request)

    # Firewall check
    if ip in blocked_ips:
        return JSONResponse(
            status_code=403,
            content={"message": "IP Blocked by Firewall"}
        )

    form = await request.form()

    event_type = form.get("event_type")
    username = form.get("username")
    status = form.get("status")

    geo = get_geo(ip)

    entry = {
        "event_type": event_type,
        "username": username,
        "status": status,
        "ip": ip,
        "geo": geo,
        "timestamp": time.time()
    }

    logs.append(entry)

    # Run brute-force detection
    check_bruteforce()

    return {"message": "Log Stored Successfully"}


# =========================================
# Get All Logs
# =========================================
@app.get("/api/logs")
def get_logs():
    return logs


# =========================================
# Clear Logs + Firewall
# =========================================
@app.delete("/api/clear-logs")
def clear_logs():
    logs.clear()
    blocked_ips.clear()
    return {"message": "Logs and blocked IPs cleared"}


# =========================================
# View Blocked IPs
# =========================================
@app.get("/api/blocked")
def get_blocked():
    return {"blocked_ips": list(blocked_ips)}


# =========================================
# Manual Unblock IP
# =========================================
@app.post("/api/unblock/{ip}")
def unblock_ip(ip: str):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        return {"message": f"{ip} unblocked successfully"}
    return {"message": "IP not in blocked list"}
