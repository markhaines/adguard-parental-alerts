"""Tests for the block-classification and alerting logic.

Both directions matter here: a miss means the alert never arrives, and a false
positive means a parent is told their child looked at adult content when they did
not. The second is the expensive one.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import monitor  # noqa: E402


def entry(reason="NotFilteredNotFound", rules=None):
    return {"reason": reason, "rules": rules or []}


def rule(text):
    return entry("FilteredBlackList", [{"text": text}])


# --- the cases the tool exists for ---------------------------------------------------


@pytest.mark.parametrize("reason", ["FilteredParental", "filteredparental", "FILTEREDPARENTAL"])
def test_parental_reason_is_adult_regardless_of_case(reason):
    assert monitor.classify_block(entry(reason=reason)) == monitor.BLOCK_ADULT


@pytest.mark.parametrize("domain", [
    "||pornhub.com^",       # keyword starts the label
    "||freeporn.com^",      # keyword ends the label
    "||youporn.com^",
    "||sex.com^",           # keyword is the whole label
    "||sextube.net^",
    "||xxx-movies.net^",
    "||nsfw.xyz^",
    "||free-adult-tube.com^",
])
def test_adult_domains_still_match(domain):
    assert monitor.classify_block(rule(domain)) == monitor.BLOCK_ADULT


def test_the_dedicated_adult_filter_list_matches_on_id_alone():
    """filter_list_id 1000001 is AdGuard's adult list, so rule text does not matter."""
    assert monitor.classify_block(
        entry("FilteredBlackList", [{"filter_list_id": 1000001}])
    ) == monitor.BLOCK_ADULT


def test_a_string_filter_list_id_still_matches():
    """AdGuard has changed query-log types before; "1000001" must not slip through."""
    assert monitor.classify_block(
        entry("FilteredBlackList", [{"filter_list_id": "1000001"}])
    ) == monitor.BLOCK_ADULT


def test_an_ordinary_allowed_query_is_not_a_block():
    assert monitor.classify_block(entry()) is None


def test_a_blocked_but_unrelated_domain_is_not_a_block():
    assert monitor.classify_block(rule("||ads.example.com^")) is None


# --- the false positives this used to raise ------------------------------------------


@pytest.mark.parametrize("domain", [
    "||essex.ac.uk^",
    "||sussex.ac.uk^",
    "||middlesex.gov.uk^",
    "||middlesexhospital.org^",
    "||wessexwater.co.uk^",
    "||adulteducation.org^",
    "||adultlearning.ac.uk^",
])
def test_innocent_domains_containing_a_keyword_are_not_adult(domain):
    """Regression: "sex" and "adult" used to be matched as bare substrings, so every
    one of these raised an "Adult Content Blocked" alert."""
    assert monitor.classify_block(rule(domain)) is None


def test_a_keyword_in_the_middle_of_a_word_does_not_match():
    """Only a whole label, a prefix or a suffix counts."""
    assert monitor.label_is_adult("middlesexhospital") is False
    assert monitor.label_is_adult("wessexwater") is False


def test_prefix_and_suffix_both_count():
    assert monitor.label_is_adult("pornhub") is True     # prefix
    assert monitor.label_is_adult("freeporn") is True    # suffix
    assert monitor.label_is_adult("porn") is True        # whole label


# --- safebrowsing is its own thing ----------------------------------------------------


def test_safebrowsing_is_classified_separately_from_adult():
    """SafeBrowsing blocks malware and phishing. Reporting those as "Adult Content
    Blocked" tells a parent something untrue about their child."""
    assert monitor.classify_block(entry(reason="FilteredSafeBrowsing")) == monitor.BLOCK_SAFEBROWSING


def test_each_category_has_its_own_notification_title():
    assert monitor.TITLES[monitor.BLOCK_ADULT] == "Adult Content Blocked"
    assert "Adult" not in monitor.TITLES[monitor.BLOCK_SAFEBROWSING]


def test_adult_wins_when_an_entry_looks_like_both():
    e = entry("FilteredSafeBrowsing", [{"text": "||pornhub.com^"}])
    assert monitor.classify_block(e) == monitor.BLOCK_ADULT


def test_is_parental_block_still_reports_anything_worth_alerting_on():
    assert monitor.is_parental_block(entry(reason="FilteredSafeBrowsing")) is True
    assert monitor.is_parental_block(rule("||pornhub.com^")) is True
    assert monitor.is_parental_block(entry()) is False


# --- shape robustness -----------------------------------------------------------------


def test_missing_and_malformed_shapes_do_not_raise():
    assert monitor.classify_block({}) is None
    assert monitor.classify_block({"rules": [{}]}) is None
    assert monitor.classify_block({"reason": None, "rules": None}) is None
    assert monitor.classify_block({"rules": ["not a dict", None]}) is None
    assert monitor.classify_block(entry("FilteredBlackList", [{"text": 12345}])) is None
    assert monitor.classify_block(entry("FilteredBlackList", [{"filter_list_id": "abc"}])) is None


# --- de-duplication -------------------------------------------------------------------


def test_trim_seen_keeps_the_most_recent_ids():
    """Regression: this was a set trimmed with set(list(seen))[-5000:], and a set has
    no order, so it kept an arbitrary 5000. Recently-alerted domains could be dropped
    and then alerted a second time."""
    seen = {f"id-{i}": None for i in range(120)}
    trimmed = monitor.trim_seen(seen, max_entries=100, keep=50)
    assert len(trimmed) == 50
    assert list(trimmed) == [f"id-{i}" for i in range(70, 120)]


def test_trim_seen_leaves_a_small_set_alone():
    seen = {f"id-{i}": None for i in range(10)}
    assert monitor.trim_seen(seen, max_entries=100, keep=50) == seen


# --- failure alerting -----------------------------------------------------------------


def test_a_healthy_poll_reports_nothing():
    assert monitor.failure_transition(0, ok=True, threshold=3) == (0, None)


def test_failures_alert_once_on_crossing_the_threshold():
    """A monitor that pages every 60 seconds gets muted, which is the same as silent."""
    count, alert = 0, None
    alerts = []
    for _ in range(6):
        count, alert = monitor.failure_transition(count, ok=False, threshold=3)
        alerts.append(alert)
    assert alerts == [None, None, "failing", None, None, None]
    assert count == 6


def test_recovery_is_reported_only_if_a_failure_was_reported():
    # Crossed the threshold, so recovery is worth saying.
    assert monitor.failure_transition(3, ok=True, threshold=3) == (0, "recovered")
    # A single blip that never alerted needs no all-clear.
    assert monitor.failure_transition(1, ok=True, threshold=3) == (0, None)


def test_the_counter_resets_on_success():
    assert monitor.failure_transition(9, ok=True, threshold=3)[0] == 0


# --- the poll loop, with AdGuard and Pushover mocked ----------------------------------


class _FakeResponse:
    status_code = 200

    def __init__(self, data):
        self._data = data

    def json(self):
        return {"data": self._data}


class _FakeSession:
    def __init__(self, data):
        self._data = data

    def get(self, *args, **kwargs):
        return _FakeResponse(self._data)


@pytest.fixture
def poll(monkeypatch):
    """Run one check_adguard() against a mocked query log; return the alerts sent."""
    sent = []
    monkeypatch.setattr(monitor, "seen_entries", {})
    monkeypatch.setattr(monitor, "consecutive_failures", 0)
    monkeypatch.setattr(monitor, "send_pushover", lambda title, message, priority=1: sent.append(message))

    def run(data):
        monkeypatch.setattr(monitor.requests, "Session", lambda: _FakeSession(data))
        monitor.check_adguard()
        return sent

    return run


def test_a_null_field_in_one_entry_does_not_fail_the_poll(poll):
    """Regression for #9: `.get(key, {})` only defaults a MISSING key, so a key present
    as null raised, failed the whole poll, and skipped every later entry in the page."""
    sent = poll([
        {"time": "1", "reason": "FilteredParental", "client_info": None, "client": "10.0.0.5",
         "question": {"name": "a.example"}},
        {"time": "2", "reason": "FilteredParental", "question": None, "client": "10.0.0.6"},
        {"time": "3", "reason": "FilteredParental", "client_info": {"name": None}, "client": "10.0.0.7",
         "question": {"name": "c.example"}},
        {"time": "4", "reason": "FilteredParental", "client_info": {"name": "Kids iPad"},
         "question": {"name": "d.example"}},
    ])
    assert monitor.consecutive_failures == 0
    assert len(sent) == 4
    assert "Client: 10.0.0.5" in sent[0]
    assert "Domain: unknown" in sent[1]
    assert "Client: 10.0.0.7" in sent[2]
    assert "Client: Kids iPad" in sent[3]


def test_an_unusable_entry_is_skipped_and_the_rest_are_still_processed(poll):
    sent = poll([
        "not an entry",
        {"time": "5", "reason": "FilteredParental", "question": {"name": "e.example"}, "client": "10.0.0.8"},
    ])
    assert monitor.consecutive_failures == 0
    assert len(sent) == 1


def test_a_page_where_every_entry_is_unreadable_counts_as_a_failed_poll(poll):
    """Skipping one bad entry must not hide a page that cannot be read at all, for
    example after a query-log format change. That is a blind monitor."""
    for _ in range(monitor.FAILURE_ALERT_AFTER):
        poll(["x", ["y"], 3])
    assert monitor.consecutive_failures == monitor.FAILURE_ALERT_AFTER


def test_an_empty_client_name_falls_back_to_the_ip_then_unknown(poll):
    """Regression for #9: a device with no AdGuard client name showed a blank `Client: `."""
    sent = poll([
        {"time": "6", "reason": "FilteredParental", "client_info": {"name": ""}, "client": "10.0.0.9",
         "question": {"name": "f.example"}},
        {"time": "7", "reason": "FilteredParental", "client_info": {"name": ""}, "client": "",
         "question": {"name": "g.example"}},
    ])
    assert "Client: 10.0.0.9" in sent[0]
    assert "Client: unknown" in sent[1]


# --- numeric settings -----------------------------------------------------------------


def test_numeric_settings_default_when_unset(monkeypatch):
    monkeypatch.delenv("POLL_INTERVAL", raising=False)
    monkeypatch.setenv("FAILURE_ALERT_AFTER", "")
    assert monitor.parse_int_setting("POLL_INTERVAL", 60, minimum=1) == 60
    assert monitor.parse_int_setting("FAILURE_ALERT_AFTER", 5, minimum=1) == 5


def test_a_valid_numeric_setting_is_read(monkeypatch):
    monkeypatch.setenv("POLL_INTERVAL", " 30 ")
    assert monitor.parse_int_setting("POLL_INTERVAL", 60, minimum=1) == 30


@pytest.mark.parametrize("name,value", [
    ("POLL_INTERVAL", "60s"),
    ("POLL_INTERVAL", "1.5"),
    ("POLL_INTERVAL", "0"),
    ("FAILURE_ALERT_AFTER", "0"),
    ("FAILURE_ALERT_AFTER", "-1"),
    ("FAILURE_ALERT_AFTER", "five"),
])
def test_a_bad_numeric_setting_is_rejected_with_its_name(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        monitor.parse_int_setting(name, 1, minimum=1)


def test_a_numeric_setting_above_its_maximum_is_rejected(monkeypatch):
    """A huge POLL_INTERVAL passed the minimum, then overflowed time.sleep after the
    first poll: a traceback and a restart loop."""
    monkeypatch.setenv("POLL_INTERVAL", "99999999999")
    with pytest.raises(ValueError, match="POLL_INTERVAL"):
        monitor.parse_int_setting("POLL_INTERVAL", 60, minimum=1, maximum=86400)
    monkeypatch.setenv("POLL_INTERVAL", "86400")
    assert monitor.parse_int_setting("POLL_INTERVAL", 60, minimum=1, maximum=86400) == 86400


def test_a_bad_numeric_setting_does_not_crash_the_import():
    """Regression for #11: `int()` ran at import, so POLL_INTERVAL=60s died with a
    traceback before main() could report it."""
    import subprocess
    env = {**os.environ, "POLL_INTERVAL": "60s", "FAILURE_ALERT_AFTER": "x"}
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run([sys.executable, "-c", "import monitor"], cwd=root, env=env,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def _main_with_required_settings(monkeypatch):
    """Set the required settings, and restore the numeric globals main() assigns."""
    monkeypatch.setattr(monitor, "POLL_INTERVAL", monitor.POLL_INTERVAL)
    monkeypatch.setattr(monitor, "FAILURE_ALERT_AFTER", monitor.FAILURE_ALERT_AFTER)
    for required in ("ADGUARD_URL", "ADGUARD_USERNAME", "ADGUARD_PASSWORD", "PUSHOVER_TOKEN", "PUSHOVER_USER"):
        monkeypatch.setattr(monitor, required, "set")


@pytest.mark.parametrize("name,value", [
    ("FAILURE_ALERT_AFTER", "0"),
    ("POLL_INTERVAL", "60s"),
    ("POLL_INTERVAL", "99999999999"),
])
def test_main_exits_1_naming_a_bad_numeric_setting(monkeypatch, caplog, name, value):
    """Regression for #11: FAILURE_ALERT_AFTER=0 meant "Failing" never fired and
    "Recovered" fired on every poll. It must be refused at startup instead."""
    _main_with_required_settings(monkeypatch)
    monkeypatch.setenv(name, value)

    def must_not_run(*args, **kwargs):
        raise AssertionError("main() went past configuration checks")

    monkeypatch.setattr(monitor, "send_pushover", must_not_run)
    monkeypatch.setattr(monitor, "check_adguard", must_not_run)
    with pytest.raises(SystemExit) as exc:
        monitor.main()
    assert exc.value.code == 1
    assert name in caplog.text


def test_main_applies_valid_numeric_settings(monkeypatch):
    """The parsed values must reach the poll loop, not just pass validation."""
    _main_with_required_settings(monkeypatch)
    monkeypatch.setenv("POLL_INTERVAL", "7")
    monkeypatch.setenv("FAILURE_ALERT_AFTER", "2")
    monkeypatch.setattr(monitor, "send_pushover", lambda *a, **k: None)
    monkeypatch.setattr(monitor, "check_adguard", lambda: None)
    slept = []

    def stop(seconds):
        slept.append(seconds)
        raise KeyboardInterrupt

    monkeypatch.setattr(monitor.time, "sleep", stop)
    with pytest.raises(KeyboardInterrupt):
        monitor.main()
    assert slept == [7]
    assert monitor.FAILURE_ALERT_AFTER == 2
