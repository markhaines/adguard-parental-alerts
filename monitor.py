#!/usr/bin/env python3
"""AdGuard Home Parental Content Monitor"""

import logging
import os
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ADGUARD_URL = os.environ.get("ADGUARD_URL", "").rstrip("/")
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")
PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "")
PUSHOVER_USER = os.environ.get("PUSHOVER_USER", "")
# Numeric settings are read and checked in main(), not here: a bad value must be
# reported by name and exit 1, not crash the import with a traceback.
POLL_INTERVAL = 60

# How many consecutive failed polls before we say so. A monitor that stops
# monitoring must not do it quietly.
FAILURE_ALERT_AFTER = 5

# Block categories. These are NOT the same thing and must not share a title:
# SafeBrowsing blocks malware and phishing, which is not a parenting matter.
BLOCK_ADULT = "adult"
BLOCK_SAFEBROWSING = "safebrowsing"

TITLES = {
    BLOCK_ADULT: "Adult Content Blocked",
    BLOCK_SAFEBROWSING: "Malware or Phishing Blocked",
}

PARENTAL_REASONS = ["filteredparental", "parental", "adult"]
SAFEBROWSING_REASONS = ["safebrowsing"]
ADULT_KEYWORDS = ["porn", "adult", "xxx", "sex", "nsfw"]
ADULT_FILTER_LIST_ID = 1000001

# Domain labels that begin or end with one of ADULT_KEYWORDS but are not adult
# content. Mostly the English counties and places ending in -sex (from the Saxons:
# Essex, Sussex, Middlesex, Wessex), which a plain substring match reported as adult
# content, plus the adult-education family. Extend this list rather than loosening
# the matcher.
KEYWORD_EXCEPTIONS = {
    "essex", "sussex", "middlesex", "wessex", "unisex", "sexton",
    "adulteducation", "adultlearning", "adultliteracy", "adultsocialcare",
}

# How many alerted entries to remember, and how many to keep when trimming.
SEEN_MAX = 10000
SEEN_KEEP = 5000

# Anything that is not a letter or digit separates one label from the next:
# "||free-porn.com^" -> ["free", "porn", "com"].
_LABEL_SPLIT = re.compile(r"[^a-z0-9]+")

# Insertion-ordered set: dict keys keep their order, a set does not.
seen_entries: dict[str, None] = {}

# Consecutive failed polls. Module-level so it survives across check_adguard calls.
consecutive_failures = 0


def send_pushover(title, message, priority=1):
    try:
        r = requests.post("https://api.pushover.net/1/messages.json",
            data={"token": PUSHOVER_TOKEN, "user": PUSHOVER_USER, "title": title,
                  "message": message, "priority": priority, "sound": "siren"}, timeout=10)
        logger.info(f"Alert sent: {title}" if r.status_code == 200 else f"Pushover error: {r.status_code}")
    except Exception as e:
        logger.error(f"Notification failed: {e}")


def parse_int_setting(name, default, minimum, maximum=None):
    """Read a whole-number environment variable, or `default` if it is unset or empty.

    Raises ValueError naming the variable if the value is not a whole number or is
    outside `minimum` to `maximum`. FAILURE_ALERT_AFTER=0, for one, would mean "Failing" never fires
    and "Recovered" fires on every poll.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a whole number, got {raw!r}") from None
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}, got {value}")
    return value


def labels(text):
    """Split a filter rule into its alphanumeric labels, lowercased."""
    return [part for part in _LABEL_SPLIT.split(str(text).lower()) if part]


def label_is_adult(label):
    """True if a single domain label looks like adult content.

    A keyword must be the whole label, or start it, or end it. It is deliberately
    NOT a bare substring match: that reported `essex.ac.uk`, `sussex.ac.uk` and
    `middlesexhospital.org` as adult content, because all three contain "sex". On a
    tool that tells a parent their child looked at adult content, a false positive
    is the expensive direction.

    Prefix and suffix both count, because real adult domains use both
    ("pornhub", "freeporn"). The handful of innocent words that still collide are
    listed in KEYWORD_EXCEPTIONS.
    """
    if label in KEYWORD_EXCEPTIONS:
        return False
    return any(
        label == kw or label.startswith(kw) or label.endswith(kw)
        for kw in ADULT_KEYWORDS
    )


def _filter_list_id(rule):
    """The rule's filter list id as an int, or None if it is missing or not a number."""
    try:
        return int(rule.get("filter_list_id"))
    except (TypeError, ValueError):
        return None


def classify_block(entry):
    """Classify a query-log entry as BLOCK_ADULT, BLOCK_SAFEBROWSING, or None.

    Order matters: the trustworthy signals (AdGuard's own parental filter, and its
    dedicated adult filter list) are checked before the keyword heuristic, and adult
    beats safebrowsing when an entry somehow looks like both.
    """
    reason = (entry.get("reason") or "").lower()
    rules = entry.get("rules") or []

    if any(r in reason for r in PARENTAL_REASONS):
        return BLOCK_ADULT

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if _filter_list_id(rule) == ADULT_FILTER_LIST_ID:
            return BLOCK_ADULT

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if any(label_is_adult(label) for label in labels(rule.get("text", ""))):
            return BLOCK_ADULT

    if any(r in reason for r in SAFEBROWSING_REASONS):
        return BLOCK_SAFEBROWSING

    return None


def is_parental_block(entry):
    """True if the entry is worth alerting on at all.

    Kept as the published name. Use classify_block when you need to know WHICH kind
    of block it was, which is what decides the notification title.
    """
    return classify_block(entry) is not None


def trim_seen(seen, max_entries=SEEN_MAX, keep=SEEN_KEEP):
    """Drop the oldest ids once `seen` grows past max_entries, keeping the newest.

    `seen` is an insertion-ordered dict rather than a set for exactly this reason.
    It used to be a set trimmed with `set(list(seen)[-5000:])`, and a set has no
    order, so that kept an arbitrary 5000 ids: recently-alerted domains could be
    dropped and alerted again, while stale ones were kept.
    """
    if len(seen) <= max_entries:
        return seen
    for key in list(seen)[: len(seen) - keep]:
        del seen[key]
    return seen


def failure_transition(consecutive, ok, threshold=None):
    """Decide what a poll's outcome means for failure alerting.

    Returns (new_consecutive, alert), where alert is None, "failing" or "recovered".
    Alerts fire once on crossing the threshold and once on recovery, never on every
    poll: a monitor that pages every 60 seconds gets muted, which is the same as
    being silent.
    """
    if threshold is None:
        threshold = FAILURE_ALERT_AFTER
    if ok:
        return 0, ("recovered" if consecutive >= threshold else None)
    new = consecutive + 1
    return new, ("failing" if new == threshold else None)


def _record_outcome(ok, detail=""):
    """Apply a poll outcome to the failure counter and alert if it crossed."""
    global consecutive_failures
    consecutive_failures, alert = failure_transition(consecutive_failures, ok)
    if alert == "failing":
        send_pushover(
            "AdGuard Monitor Failing",
            f"{consecutive_failures} consecutive failed polls of {ADGUARD_URL}.\n"
            f"Adult-content alerts are NOT being delivered.\n{detail}".strip(),
        )
    elif alert == "recovered":
        send_pushover(
            "AdGuard Monitor Recovered",
            f"Polling {ADGUARD_URL} again. Alerts are being delivered.",
            priority=0,
        )


def check_adguard():
    global seen_entries
    try:
        s = requests.Session()
        s.auth = (ADGUARD_USERNAME, ADGUARD_PASSWORD)
        s.verify = False
        r = s.get(f"{ADGUARD_URL}/control/querylog", params={"limit": 100}, timeout=30)
        if r.status_code != 200:
            logger.error(f"API error: {r.status_code}")
            _record_outcome(False, f"Last status: HTTP {r.status_code}")
            return
        data = r.json().get("data", [])
        unreadable = 0
        for e in data:
            # One odd entry is logged and skipped. It must not fail the whole poll,
            # or it blinds the monitor until it ages out of the page.
            try:
                # `or {}`, not a .get default: AdGuard can send these keys as null.
                domain = (e.get("question") or {}).get("name") or "unknown"
                eid = f"{e.get('time', '')}-{domain}"
                if eid in seen_entries:
                    continue
                category = classify_block(e)
                if category:
                    seen_entries[eid] = None
                    client = (e.get("client_info") or {}).get("name") or e.get("client") or "unknown"
                    send_pushover(
                        TITLES[category],
                        f"Domain: {domain}\nClient: {client}\nReason: {e.get('reason', 'unknown')}",
                    )
            except Exception as ex:
                unreadable += 1
                logger.error(f"Skipping unreadable query-log entry: {ex}")
        seen_entries = trim_seen(seen_entries)
        # A page with nothing readable on it is a blind monitor, not a healthy poll.
        if data and unreadable == len(data):
            _record_outcome(False, f"Last error: all {unreadable} query-log entries unreadable")
            return
        _record_outcome(True)
    except Exception as ex:
        logger.error(f"Error: {ex}")
        _record_outcome(False, f"Last error: {ex}")


def main():
    global POLL_INTERVAL, FAILURE_ALERT_AFTER
    missing = [n for n, v in [("ADGUARD_URL", ADGUARD_URL), ("ADGUARD_USERNAME", ADGUARD_USERNAME),
        ("ADGUARD_PASSWORD", ADGUARD_PASSWORD), ("PUSHOVER_TOKEN", PUSHOVER_TOKEN), ("PUSHOVER_USER", PUSHOVER_USER)] if not v]
    if missing:
        logger.error(f"Missing: {', '.join(missing)}")
        sys.exit(1)
    try:
        POLL_INTERVAL = parse_int_setting("POLL_INTERVAL", 60, minimum=1, maximum=86400)
        FAILURE_ALERT_AFTER = parse_int_setting("FAILURE_ALERT_AFTER", 5, minimum=1)
    except ValueError as ex:
        logger.error(f"Invalid configuration: {ex}")
        sys.exit(1)
    logger.info(f"Starting monitor - {ADGUARD_URL} every {POLL_INTERVAL}s")
    send_pushover("Monitor Started", f"Watching: {ADGUARD_URL}", priority=0)
    while True:
        check_adguard()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
