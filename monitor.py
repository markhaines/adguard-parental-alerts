#!/usr/bin/env python3
"""AdGuard Home Parental Content Monitor"""

import os, sys, time, logging, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ADGUARD_URL = os.environ.get("ADGUARD_URL", "").rstrip("/")
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")
PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "")
PUSHOVER_USER = os.environ.get("PUSHOVER_USER", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", 60))
ADULT_FILTER_IDS = {
    int(value.strip()) for value in os.environ.get("ADULT_FILTER_IDS", "").split(",") if value.strip()
}

seen_entries = set()

def send_pushover(title, message, priority=1):
    try:
        r = requests.post("https://api.pushover.net/1/messages.json",
            data={"token": PUSHOVER_TOKEN, "user": PUSHOVER_USER, "title": title,
                  "message": message, "priority": priority, "sound": "siren"}, timeout=10)
        logger.info(f"Alert sent: {title}" if r.status_code == 200 else f"Pushover error: {r.status_code}")
    except Exception as e:
        logger.error(f"Notification failed: {e}")

def is_parental_block(entry):
    if entry.get("reason") == "FilteredParental":
        return True
    for rule in entry.get("rules", []):
        if rule.get("filter_list_id") in ADULT_FILTER_IDS:
            return True
    return False

def check_adguard():
    global seen_entries
    try:
        s = requests.Session()
        s.auth = (ADGUARD_USERNAME, ADGUARD_PASSWORD)
        s.verify = False
        r = s.get(f"{ADGUARD_URL}/control/querylog", params={"limit": 100}, timeout=30)
        if r.status_code != 200:
            logger.error(f"API error: {r.status_code}")
            return
        for e in r.json().get("data", []):
            domain = e.get("question", {}).get("name", "unknown")
            eid = f"{e.get('time', '')}-{domain}"
            if eid in seen_entries:
                continue
            if is_parental_block(e):
                seen_entries.add(eid)
                client = e.get("client_info", {}).get("name", e.get("client", "unknown"))
                send_pushover("Adult Content Blocked", f"Domain: {domain}\nClient: {client}\nReason: {e.get('reason', 'unknown')}")
        if len(seen_entries) > 10000:
            seen_entries = set(list(seen_entries)[-5000:])
    except Exception as ex:
        logger.error(f"Error: {ex}")

def main():
    missing = [n for n, v in [("ADGUARD_URL", ADGUARD_URL), ("ADGUARD_USERNAME", ADGUARD_USERNAME),
        ("ADGUARD_PASSWORD", ADGUARD_PASSWORD), ("PUSHOVER_TOKEN", PUSHOVER_TOKEN), ("PUSHOVER_USER", PUSHOVER_USER)] if not v]
    if missing:
        logger.error(f"Missing: {', '.join(missing)}")
        sys.exit(1)
    logger.info(f"Starting monitor - {ADGUARD_URL} every {POLL_INTERVAL}s")
    send_pushover("Monitor Started", f"Watching: {ADGUARD_URL}", priority=0)
    while True:
        check_adguard()
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
