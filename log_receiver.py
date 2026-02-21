from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import time
from collections import defaultdict

app = FastAPI()

logs = []
blocked_ips = set()

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300

def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host

def calculate_risk(event_type):
    if event_type == "bruteforce":
        return 8
    if event_type == "sql_injection":
        return 9
    if event_type == "xss_attack":
        return 7
    return 3

def check_bruteforce():
    now = time.time()
    fail_counter = defaultdict(int)

    for log in logs:
        if log["event_type"] == "login" and log["status"] == "failed":
            if now - log["timestamp"] <= BRUTE_FORCE_WINDOW:
                fail_counter[log["ip"]] += 1

    for ip, count in fail_counter.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            blocked_ips.add(ip)

@app.post("/api/log")
async def receive_log(request: Request):

    ip = get_client_ip(request)

    if ip in blocked_ips:
        return JSONResponse(status_code=403, content={"message": "IP Blocked"})

    form = await request.form()
    event_type = form.get("event_type")
    username = form.get("username")
    status = form.get("status")

    risk_score = calculate_risk(event_type)

    entry = {
        "event_type": event_type,
        "username": username,
        "status": status,
        "ip": ip,
        "risk_score": risk_score,
        "timestamp": time.time()
    }

    logs.append(entry)

    check_bruteforce()

    return {"message": "Log stored"}

@app.get("/api/logs")
def get_logs():
    return logs

@app.get("/api/blocked")
def get_blocked():
    return {"blocked_ips": list(blocked_ips)}

@app.delete("/api/clear")
def clear_logs():
    logs.clear()
    blocked_ips.clear()
    return {"message": "Cleared"}
