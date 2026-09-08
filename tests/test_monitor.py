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
