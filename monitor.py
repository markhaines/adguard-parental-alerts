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
POLL_INTERVAL = 60
ADULT_FILTER_IDS = set()

seen_entries = set()

def parse_adult_filter_ids(value):
    filter_ids = set()
    for token in (value or "").split(","):
        token = token.strip()
        if not token:
            continue
        if not token.isascii() or not token.isdigit() or int(token) < 0:
            raise ValueError(
                f"invalid ADULT_FILTER_IDS value {token!r}; expected comma-separated non-negative "
                "integers (for example: 0,42)"
            )
        filter_ids.add(int(token))
    return filter_ids

def parse_poll_interval(value):
    if value is None:
        return 60
    token = value.strip()
    if not token.isascii() or not token.isdigit() or not 1 <= int(token) <= 86400:
        raise ValueError(
            f"invalid POLL_INTERVAL value {value!r}; expected an integer from 1 to 86400 seconds "
            "(for example: 60)"
        )
    return int(token)

def validate_configuration():
    global ADULT_FILTER_IDS, POLL_INTERVAL
    try:
        POLL_INTERVAL = parse_poll_interval(os.environ.get("POLL_INTERVAL"))
        ADULT_FILTER_IDS = parse_adult_filter_ids(os.environ.get("ADULT_FILTER_IDS"))
    except ValueError as exc:
        logger.error(f"Invalid configuration: {exc}")
        sys.exit(1)

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
    if entry.get("reason") != "FilteredBlackList":
        return False
    for rule in entry.get("rules") or []:
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
    validate_configuration()
    logger.info(f"Starting monitor - {ADGUARD_URL} every {POLL_INTERVAL}s")
    send_pushover("Monitor Started", f"Watching: {ADGUARD_URL}", priority=0)
    while True:
        check_adguard()
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
