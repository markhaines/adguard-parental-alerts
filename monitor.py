#!/usr/bin/env python3
"""AdGuard Home Parental Content Monitor

Delivery is at-least-once: an alert leaves the outbox only after Pushover
accepts it, so a crash between Pushover accepting the message and the state
save can produce a duplicate notification on restart - never a lost one.

Event loss is never silent. Every condition that may discard events (lost
cursor, outbox overflow, permanently rejected alert, exhausted retries)
also queues a durable Pushover notice to the operator ahead of ordinary
alerts. Notices travel through the same persistent outbox as alerts (so a
lost event is reported at-least-once), are exempt from overflow trimming,
and are never dropped through attempt exhaustion: they retry at a capped
cadence until Pushover accepts them. Recurring incidents aggregate into the
still-queued notice (occurrence count and time window extended) instead of
being suppressed, so the operator always sees how many incidents happened.
Delivery failures that indicate a Pushover configuration fault (invalid
token or user key) never delete queued alerts; the queue is preserved until
the configuration is fixed.
"""

import json, os, sys, time, logging, ssl, requests, urllib3

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def tls_verification_enabled(value):
    return value.strip().lower() not in ("0", "false", "no")

def tls_verification_setting_known(value):
    return value.strip().lower() in ("0", "false", "no", "1", "true", "yes")

ADGUARD_URL = os.environ.get("ADGUARD_URL", "").rstrip("/")
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")
PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "")
PUSHOVER_USER = os.environ.get("PUSHOVER_USER", "")
POLL_INTERVAL = 60
ADULT_FILTER_IDS = set()
VERIFY_TLS_SETTING = os.environ.get("VERIFY_TLS", "true")
VERIFY_TLS = tls_verification_enabled(VERIFY_TLS_SETTING)
ADGUARD_CA_BUNDLE = os.environ.get("ADGUARD_CA_BUNDLE", "")
if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")
QUERY_PAGE_SIZE = int(os.environ.get("QUERY_PAGE_SIZE", 100))
MAX_QUERY_PAGES = int(os.environ.get("MAX_QUERY_PAGES", 100))
# 500 keeps the outbox small enough to stay well under Pushover's monthly
# message allowance while a home daemon at a 60s poll would need a sustained
# outage to fill it; when it does fill, the newest activity is the part worth
# knowing about.
MAX_PENDING_ALERTS = int(os.environ.get("MAX_PENDING_ALERTS", 500))
MAX_ALERT_ATTEMPTS = int(os.environ.get("MAX_ALERT_ATTEMPTS", 5))
ALERT_BACKOFF_BASE = int(os.environ.get("ALERT_BACKOFF_BASE", 60))
# Notices retry indefinitely at this capped cadence: they are tiny, few and
# trim-exempt, so unbounded retry is safe, and they must never vanish through
# attempt exhaustion (that would make a loss condition silently disappear).
NOTICE_BACKOFF_CEILING = 3600
# Batch state fsyncs: a crash loses at most one batch of attempt counters
# (the affected items stay queued and are retried) - never a queued item.
STATE_SAVE_INTERVAL = 25

def parse_adult_filter_ids(value):
    filter_ids = set()
    for token in (value or "").split(","):
        token = token.strip()
        if not token:
            continue
        if not token.isascii() or not token.isdigit():
            raise ValueError(
                f"invalid ADULT_FILTER_IDS value {token!r}; expected comma-separated "
                "non-negative integers (for example: 0,42)")
        filter_ids.add(int(token))
    return filter_ids


def parse_poll_interval(value):
    if value is None:
        return 60
    token = value.strip()
    if not token.isascii() or not token.isdigit() or not 1 <= int(token) <= 86400:
        raise ValueError(
            f"invalid POLL_INTERVAL value {value!r}; expected an integer from 1 to "
            "86400 seconds (for example: 60)")
    return int(token)


def validate_configuration():
    global ADULT_FILTER_IDS, POLL_INTERVAL
    try:
        POLL_INTERVAL = parse_poll_interval(os.environ.get("POLL_INTERVAL"))
        ADULT_FILTER_IDS = parse_adult_filter_ids(os.environ.get("ADULT_FILTER_IDS"))
    except ValueError as ex:
        logger.error(f"Invalid configuration: {ex}")
        sys.exit(1)

DELIVERY_OK = "ok"
DELIVERY_TRANSIENT = "transient"
DELIVERY_PERMANENT = "permanent"
DELIVERY_CONFIG = "config"

def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as state_file:
            state = json.load(state_file)
    except FileNotFoundError:
        return {"version": 2, "cursor": None, "pending": [], "initialised": False}
    except (OSError, ValueError) as ex:
        raise RuntimeError(f"Cannot load state from {STATE_FILE}: {ex}") from ex
    if state.get("version", 1) < 2:
        # Pre-version state files were only ever written after a baseline was
        # established (the cursor is set on every save), so an existing file
        # means the monitor was already initialised. Missing cursor plus no
        # version can only come from an empty-log initialisation, which is
        # also initialised. Never re-baseline an existing state file.
        initialised = True
    else:
        initialised = state.get("initialised", False)
    return {
        "version": 2,
        "cursor": state.get("cursor"),
        "pending": state.get("pending", []),
        "initialised": initialised,
    }


def save_state(state):
    directory = os.path.dirname(STATE_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = f"{STATE_FILE}.tmp"
    state["version"] = 2
    with open(temporary, "w", encoding="utf-8") as state_file:
        json.dump(state, state_file)
        state_file.flush()
        os.fsync(state_file.fileno())
    os.replace(temporary, STATE_FILE)
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as ex:
        logger.warning(f"Could not fsync state directory {directory}: {ex}")


def entry_id(entry):
    question = entry.get("question", {})
    return "|".join((
        entry.get("time", ""),
        question.get("name", ""),
        entry.get("client", ""),
        question.get("type", ""),
    ))


def _fmt_ts(ts):
    if not ts:
        return "unknown"
    if isinstance(ts, (int, float)):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    return str(ts)


def _fmt_window(start_ts, end_ts):
    return f"{_fmt_ts(start_ts)} to {_fmt_ts(end_ts)}"


def _compose_notice_message(base, count, start, end):
    if count > 1:
        return (f"{base}\nOccurrences: {count}\n"
                f"First detected: {_fmt_ts(start)}\nLast detected: {_fmt_ts(end)}")
    return f"{base}\nDetected: {_fmt_ts(start)}"


def _notify_once(state, name, title, base_message, extra=(), skip=()):
    """Record a loss condition as a durable, aggregated operator notice.

    Notices are never dropped and never suppressed. If a notice for this
    condition is still queued, the recurrence folds into it (occurrence count
    incremented, time window extended); once the earlier notice has been
    delivered, a recurrence queues a fresh one. The caller splices the
    returned notice into the outbox - this function never mutates the list
    being iterated. Returns (notice, created), where created is False when an
    existing queued notice was aggregated instead.
    """
    now = time.time()
    for existing in list(state["pending"]) + list(extra):
        if existing.get("kind") != "notice" or existing.get("name") != name:
            continue
        if id(existing) in skip:
            continue
        existing["count"] = existing.get("count", 1) + 1
        existing["window_end"] = now
        existing["message"] = _compose_notice_message(
            base_message, existing["count"], existing["window_start"], existing["window_end"])
        return existing, False
    notice = {
        "kind": "notice",
        "name": name,
        "id": f"notice:{name}:{int(now)}",
        "title": title,
        "count": 1,
        "window_start": now,
        "window_end": now,
        "ts": now,
        "message": _compose_notice_message(base_message, 1, now, now),
    }
    return notice, True


def send_pushover(title, message, priority=1):
    try:
        r = requests.post("https://api.pushover.net/1/messages.json",
            data={"token": PUSHOVER_TOKEN, "user": PUSHOVER_USER, "title": title,
                  "message": message, "priority": priority, "sound": "siren"}, timeout=10)
        if r.status_code == 200 and r.json().get("status") == 1:
            logger.info(f"Alert sent: {title}")
            return DELIVERY_OK
        if r.status_code in (401, 404):
            # 401 = invalid application token, 404 = invalid or missing user
            # or group key. That is a configuration fault, not a message
            # fault: queued alerts are kept and retried slowly rather than
            # deleted, and the log carries the loud failure signal.
            logger.error(
                f"Pushover rejected the request ({r.status_code}): invalid "
                f"token or user key, check PUSHOVER_TOKEN and PUSHOVER_USER. "
                f"Queued alerts are being kept: {title}")
            return DELIVERY_CONFIG
        if r.status_code == 400:
            logger.error(f"Pushover rejected the request (400): invalid "
                         f"message parameters: {title}")
            return DELIVERY_PERMANENT
        # 429 (rate limit), 5xx (server fault), and any other unexpected
        # status (e.g. 408) are transient: retry later.
        logger.warning(f"Pushover temporarily unavailable ({r.status_code}): {title}")
        return DELIVERY_TRANSIENT
    except Exception as ex:
        logger.error(f"Notification failed: {ex}")
        return DELIVERY_TRANSIENT

def is_parental_block(entry):
    if entry.get("reason") == "FilteredParental":
        return True
    if entry.get("reason") != "FilteredBlackList":
        return False
    for rule in entry.get("rules") or []:
        # Rewrites and whitelist matches have different reasons and therefore
        # never reach this branch, including filter ID 0.
        if rule.get("filter_list_id") in ADULT_FILTER_IDS:
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
    # The outbox is iterated over an immutable snapshot and rebuilt
    # separately, so a notice queued mid-pass can never shift the iteration
    # and reprocess an item.
    #
    # Alerts retry with exponential backoff and are dropped only on permanent
    # rejection (HTTP 400) or after MAX_ALERT_ATTEMPTS, each drop queueing a
    # durable notice. A configuration fault (invalid token/user key) never
    # deletes alerts - they stay queued and retry slowly.
    #
    # Notices themselves retry indefinitely at a capped cadence and leave the
    # outbox only when Pushover accepts them; they never recurse into more
    # notices and are never deleted through attempt exhaustion.
    #
    # State is saved in batches (every STATE_SAVE_INTERVAL processed items
    # and at the end), so a crash loses at most one batch of attempt counters
    # - never a queued item.
    snapshot = list(state["pending"])
    remaining = []
    new_notices = []
    delivered_ids = set()
    dirty = False
    processed = 0
    for index, alert in enumerate(snapshot):
        now = time.time()
        if alert.get("next_attempt") and alert["next_attempt"] > now:
            remaining.append(alert)
            continue
        if alert.get("kind") == "notice":
            result = send_pushover(alert["title"], alert["message"])
            if result == DELIVERY_OK:
                logger.info(f"Notice delivered: {alert['title']}")
                delivered_ids.add(id(alert))
            else:
                alert["attempts"] = alert.get("attempts", 0) + 1
                alert["next_attempt"] = now + min(
                    ALERT_BACKOFF_BASE * (2 ** (alert["attempts"] - 1)),
                    NOTICE_BACKOFF_CEILING)
                remaining.append(alert)
            dirty = True
            processed += 1
        else:
            result = send_pushover(alert["title"], alert["message"])
            if result == DELIVERY_OK:
                logger.info(f"Alert delivered: {alert['title']}")
            elif result == DELIVERY_PERMANENT:
                logger.error(f"Dropping permanently rejected alert: {alert['title']}")
                notice, created = _notify_once(state, "permanent-reject",
                    "Alert dropped: Pushover rejected it",
                    f"{alert['title']}: {alert['message']}",
                    extra=new_notices, skip=delivered_ids)
                if created:
                    new_notices.append(notice)
            elif result == DELIVERY_CONFIG:
                # Configuration fault: never drop the alert, retry on a slow
                # cadence, and let the log carry the loud signal (a Pushover
                # notice would be futile while the credentials are wrong).
                alert["next_attempt"] = now + ALERT_BACKOFF_BASE * 8
                remaining.append(alert)
            else:
                alert["attempts"] = alert.get("attempts", 0) + 1
                if alert["attempts"] >= MAX_ALERT_ATTEMPTS:
                    logger.warning(
                        f"Dropping alert after {alert['attempts']} failed attempts: {alert['title']}")
                    notice, created = _notify_once(state, "attempts-exhausted",
                        "Alert dropped: delivery retries exhausted",
                        f"{alert['title']}: {alert['message']}",
                        extra=new_notices, skip=delivered_ids)
                    if created:
                        new_notices.append(notice)
                else:
                    alert["next_attempt"] = now + ALERT_BACKOFF_BASE * (2 ** (alert["attempts"] - 1))
                    remaining.append(alert)
            dirty = True
            processed += 1
        if dirty and processed % STATE_SAVE_INTERVAL == 0:
            state["pending"] = new_notices + remaining + snapshot[index + 1:]
            save_state(state)
            dirty = False
    if dirty:
        state["pending"] = new_notices + remaining
        save_state(state)


def check_adguard(state):
    try:
        s = requests.Session()
        s.auth = (ADGUARD_USERNAME, ADGUARD_PASSWORD)
        s.verify = ADGUARD_CA_BUNDLE if VERIFY_TLS and ADGUARD_CA_BUNDLE else VERIFY_TLS
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
                f"the newest available entry.")
            notice, created = _notify_once(state, "cursor-gap", "AdGuard monitoring gap detected",
                f"Events older than the newest {len(entries)} query-log entries "
                f"(scanned up to {MAX_QUERY_PAGES * QUERY_PAGE_SIZE}) may have been "
                f"missed. The monitor has re-baselined to the newest entry and "
                f"continues.")
            if created:
                state["pending"].insert(0, notice)

        seen = {alert["id"] for alert in state["pending"]}
        for e in reversed(entries):
            domain = e.get("question", {}).get("name", "unknown")
            eid = entry_id(e)
            if is_parental_block(e) and eid not in seen:
                seen.add(eid)
                client = e.get("client_info", {}).get("name", e.get("client", "unknown"))
                state["pending"].append({"id": eid, "title": "Adult Content Blocked",
                    "message": f"Domain: {domain}\nClient: {client}\nReason: {e.get('reason', 'unknown')}",
                    "ts": e.get("time")})
        if entries:
            state["cursor"] = entry_id(entries[0])
        save_state(state)
        deliver_pending(state)
        notices = [a for a in state["pending"] if a.get("kind") == "notice"]
        alerts = [a for a in state["pending"] if a.get("kind") != "notice"]
        if len(alerts) > MAX_PENDING_ALERTS:
            dropped = len(alerts) - MAX_PENDING_ALERTS
            window = _fmt_window(alerts[0].get("ts"), alerts[dropped - 1].get("ts"))
            state["pending"] = notices + alerts[dropped:]
            logger.warning(
                f"Undelivered alert queue exceeded {MAX_PENDING_ALERTS}; "
                f"dropped the {dropped} oldest undelivered alert(s) "
                f"(time window {window})")
            notice, created = _notify_once(state, "outbox-overflow", "AdGuard alerts dropped",
                f"{dropped} undelivered alerts were dropped because the queue "
                f"exceeded {MAX_PENDING_ALERTS}. Affected time window: {window}. "
                f"Check Pushover delivery.")
            if created:
                state["pending"].insert(0, notice)
            save_state(state)
    except Exception as ex:
        logger.error(f"Error: {ex}")

def main():
    missing = [n for n, v in [("ADGUARD_URL", ADGUARD_URL), ("ADGUARD_USERNAME", ADGUARD_USERNAME),
        ("ADGUARD_PASSWORD", ADGUARD_PASSWORD), ("PUSHOVER_TOKEN", PUSHOVER_TOKEN), ("PUSHOVER_USER", PUSHOVER_USER)] if not v]
    if missing:
        logger.error(f"Missing: {', '.join(missing)}")
        sys.exit(1)
    validate_configuration()
    if not VERIFY_TLS:
        logger.warning("TLS certificate verification is DISABLED for AdGuard connections (VERIFY_TLS=false)")
    elif not tls_verification_setting_known(VERIFY_TLS_SETTING):
        logger.warning(
            f"Unrecognized VERIFY_TLS value {VERIFY_TLS_SETTING!r}; TLS verification remains "
            "ENABLED. Use 0, false, or no to disable it.")
    # A CA bundle only affects HTTPS. Do not reject a stale/missing CA path
    # for an explicitly plain-HTTP AdGuard endpoint.
    if VERIFY_TLS and ADGUARD_URL.lower().startswith("https://") and ADGUARD_CA_BUNDLE:
        if not (os.path.isfile(ADGUARD_CA_BUNDLE) and os.access(ADGUARD_CA_BUNDLE, os.R_OK)):
            logger.error(
                f"ADGUARD_CA_BUNDLE is not a readable file: {ADGUARD_CA_BUNDLE}. "
                "Mount the CA certificate into the container and use its in-container path.")
            sys.exit(1)
        try:
            ssl.create_default_context(cafile=ADGUARD_CA_BUNDLE)
        except (OSError, ssl.SSLError) as ex:
            logger.error(
                f"ADGUARD_CA_BUNDLE is not a valid PEM certificate bundle: "
                f"{ADGUARD_CA_BUNDLE} ({ex})")
            sys.exit(1)
    logger.info(f"Starting monitor - {ADGUARD_URL} every {POLL_INTERVAL}s")
    startup_result = send_pushover("Monitor Started", f"Watching: {ADGUARD_URL}", priority=0)
    if startup_result == DELIVERY_CONFIG:
        logger.error(
            "Pushover rejected the startup message with a configuration error "
            "(invalid token or user key). Check PUSHOVER_TOKEN and PUSHOVER_USER; "
            "queued alerts will be kept and retried slowly until fixed.")
    state = load_state()
    while True:
        check_adguard(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
