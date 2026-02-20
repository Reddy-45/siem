from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import json
import os
import time

app = FastAPI()

# Allow external requests (important for PHP hosting)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE = "logs/firewall_logs.json"

# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)

# ------------------------------
# RECEIVE LOG
# ------------------------------
@app.post("/api/log")
async def receive_log(request: Request):

    form_data = await request.form()

    log_entry = {
        "event_type": form_data.get("event_type", "unknown"),
        "username": form_data.get("username", "unknown"),
        "status": form_data.get("status", "unknown"),
        "ip": request.client.host,
        "timestamp": float(time.time())
    }

    logs = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except:
            logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    return {"message": "Log stored successfully"}


# ------------------------------
# GET ALL LOGS
# ------------------------------
@app.get("/api/logs")
def get_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    return []


# ------------------------------
# CLEAR LOGS
# ------------------------------
@app.delete("/api/clear")
def clear_logs():
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
    return {"message": "Logs cleared"}


# ------------------------------
# RENDER STARTUP CONFIG
# ------------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("log_receiver:app", host="0.0.0.0", port=port)