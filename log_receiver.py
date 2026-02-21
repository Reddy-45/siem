from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from collections import defaultdict
import subprocess
import time
import requests

app = FastAPI(title="AI-SIEM Autonomous")

# ==============================
# Storage
# ==============================
logs = []
blocked_ips = set()
ai_reports = []

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 min


# ==============================
# Version
# ==============================
@app.get("/")
def root():
    return {"version": "AI-SIEM v3 - Autonomous LLM Enabled"}


# ==============================
# Get Client IP
# ==============================
def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


# ==============================
# Geolocation
# ==============================
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


# ==============================
# Local LLM Generator
# ==============================
def generate_ai_report(ip, attempts, geo):

    prompt = f"""
    A brute force attack was detected.

    IP: {ip}
    Failed Attempts (last 5 minutes): {attempts}
    Country: {geo.get('country')}
    ISP: {geo.get('isp')}

    Provide:
    1. Incident Summary
    2. Risk Score (1-10)
    3. Possible Impact
    4. Prevention Measures
    5. SOC Recommended Actions
    """

    try:
        result = subprocess.run(
            ["ollama", "run", "mistral"],
            input=prompt.encode(),
            stdout=subprocess.PIPE
        )

        output = result.stdout.decode()

        report = {
            "ip": ip,
            "analysis": output,
            "timestamp": time.time()
        }

        ai_reports.append(report)

    except Exception as e:
        print("LLM Error:", e)


# ==============================
# Brute Force Detection
# ==============================
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
        if count >= BRUTE_FORCE_THRESHOLD and ip not in blocked_ips:
            blocked_ips.add(ip)

            geo = next((l["geo"] for l in logs if l["ip"] == ip), {})

            # 🔥 AUTO LLM TRIGGER
            generate_ai_report(ip, count, geo)


# ==============================
# Receive Log
# ==============================
@app.post("/api/log")
async def receive_log(request: Request):

    ip = get_client_ip(request)

    if ip in blocked_ips:
        return JSONResponse(
            status_code=403,
            content={"message": "IP Blocked"}
        )

    form = await request.form()

    entry = {
        "event_type": form.get("event_type"),
        "username": form.get("username"),
        "status": form.get("status"),
        "ip": ip,
        "geo": get_geo(ip),
        "timestamp": time.time()
    }

    logs.append(entry)

    check_bruteforce()

    return {"message": "Log Stored"}


# ==============================
# APIs
# ==============================
@app.get("/api/logs")
def get_logs():
    return logs


@app.get("/api/blocked")
def get_blocked():
    return {"blocked_ips": list(blocked_ips)}


@app.get("/api/ai-reports")
def get_ai_reports():
    return ai_reports


@app.delete("/api/clear-logs")
def clear_logs():
    logs.clear()
    blocked_ips.clear()
    ai_reports.clear()
    return {"message": "Cleared"}
