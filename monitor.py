#!/usr/bin/env python3
"""AdGuard Home Parental Content Monitor

Delivery is at-least-once: an alert leaves the outbox only after Pushover
accepts it, so a crash between Pushover accepting the message and the state
save can produce a duplicate notification on restart - never a lost one.
"""

import json, os, sys, time, logging, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ADGUARD_URL = os.environ.get("ADGUARD_URL", "").rstrip("/")
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")
PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "")
PUSHOVER_USER = os.environ.get("PUSHOVER_USER", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", 60))
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")
QUERY_PAGE_SIZE = int(os.environ.get("QUERY_PAGE_SIZE", 100))
MAX_QUERY_PAGES = int(os.environ.get("MAX_QUERY_PAGES", 100))
MAX_PENDING_ALERTS = int(os.environ.get("MAX_PENDING_ALERTS", 100))

PARENTAL_REASONS = ["filteredparental", "parental", "adult", "safebrowsing"]
ADULT_KEYWORDS = ["porn", "adult", "xxx", "sex", "nsfw"]

def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as state_file:
            state = json.load(state_file)
    except FileNotFoundError:
        return {"cursor": None, "pending": [], "initialised": False}
    except (OSError, ValueError) as ex:
        raise RuntimeError(f"Cannot load state from {STATE_FILE}: {ex}") from ex
    return {
        "cursor": state.get("cursor"),
        "pending": state.get("pending", []),
        "initialised": state.get("initialised", state.get("cursor") is not None),
    }


def save_state(state):
    directory = os.path.dirname(STATE_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = f"{STATE_FILE}.tmp"
    with open(temporary, "w", encoding="utf-8") as state_file:
        json.dump(state, state_file)
        state_file.flush()
        os.fsync(state_file.fileno())
    os.replace(temporary, STATE_FILE)


def entry_id(entry):
    question = entry.get("question", {})
    return "|".join((
        entry.get("time", ""),
        question.get("name", ""),
        entry.get("client", ""),
        question.get("type", ""),
        str(entry.get("elapsedMs", "")),
    ))

def send_pushover(title, message, priority=1):
    try:
        r = requests.post("https://api.pushover.net/1/messages.json",
            data={"token": PUSHOVER_TOKEN, "user": PUSHOVER_USER, "title": title,
                  "message": message, "priority": priority, "sound": "siren"}, timeout=10)
        accepted = r.status_code == 200 and r.json().get("status") == 1
        logger.info(f"Alert sent: {title}" if accepted else f"Pushover rejected alert: {r.status_code}")
        return accepted
    except Exception as e:
        logger.error(f"Notification failed: {e}")
        return False

def is_parental_block(entry):
    reason = entry.get("reason", "").lower()
    if any(r in reason for r in PARENTAL_REASONS):
        return True
    for rule in entry.get("rules", []):
        if any(kw in str(rule.get("text", "")).lower() for kw in ADULT_KEYWORDS):
            return True
        if rule.get("filter_list_id", 0) == 1000001:
            return True
    return False

def fetch_since(session, cursor):
    entries = []
    found_cursor = False
    for page in range(MAX_QUERY_PAGES):
        r = session.get(f"{ADGUARD_URL}/control/querylog",
            params={"limit": QUERY_PAGE_SIZE, "offset": page * QUERY_PAGE_SIZE}, timeout=30)
        r.raise_for_status()
        page_entries = r.json().get("data", [])
        for entry in page_entries:
            if cursor and entry_id(entry) == cursor:
                found_cursor = True
                break
            entries.append(entry)
        if found_cursor or len(page_entries) < QUERY_PAGE_SIZE:
            break
    return entries, found_cursor


def deliver_pending(state):
    # At-least-once: an alert is removed only after Pushover accepts it, so a
    # crash between accept and the state save can re-deliver it on restart.
    # A failed alert does not block later alerts from being attempted.
    remaining = []
    for alert in state["pending"]:
        if send_pushover(alert["title"], alert["message"]):
            logger.info(f"Alert delivered: {alert['title']}")
        else:
            remaining.append(alert)
    if len(remaining) != len(state["pending"]):
        state["pending"] = remaining
        save_state(state)


def check_adguard(state):
    try:
        s = requests.Session()
        s.auth = (ADGUARD_USERNAME, ADGUARD_PASSWORD)
        s.verify = False
        entries, cursor_found = fetch_since(s, state["cursor"])

        if not state.get("initialised"):
            if entries:
                state["cursor"] = entry_id(entries[0])
            state["initialised"] = True
            save_state(state)
            if entries:
                logger.info("Initial query-log position recorded; historical entries skipped")
            else:
                logger.info("Initialised against an empty query log; awaiting first entries")
            return

        if state["cursor"] and not cursor_found:
            logger.warning(
                f"Saved cursor was not found in the query log (log rotated/cleared "
                f"or the backlog exceeded {MAX_QUERY_PAGES} pages); re-baselining to "
                f"the newest available entry. Events since the old cursor cannot be "
                f"recovered.")

        seen = {alert["id"] for alert in state["pending"]}
        for e in reversed(entries):
            domain = e.get("question", {}).get("name", "unknown")
            eid = entry_id(e)
            if is_parental_block(e) and eid not in seen:
                seen.add(eid)
                client = e.get("client_info", {}).get("name", e.get("client", "unknown"))
                state["pending"].append({"id": eid, "title": "Adult Content Blocked",
                    "message": f"Domain: {domain}\nClient: {client}\nReason: {e.get('reason', 'unknown')}"})
        if len(state["pending"]) > MAX_PENDING_ALERTS:
            dropped = len(state["pending"]) - MAX_PENDING_ALERTS
            state["pending"] = state["pending"][-MAX_PENDING_ALERTS:]
            logger.warning(
                f"Undelivered alert queue exceeded {MAX_PENDING_ALERTS}; "
                f"dropped the {dropped} oldest alert(s)")
        if entries:
            state["cursor"] = entry_id(entries[0])
        save_state(state)
        deliver_pending(state)
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
    state = load_state()
    while True:
        check_adguard(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
