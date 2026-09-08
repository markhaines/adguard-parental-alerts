"""Tests for the block-classification logic.

`is_parental_block` decides whether a query-log entry is worth waking a parent for,
so both directions matter: a miss means the alert never arrives, and a false positive
means a parent is told their child visited adult content when they did not.

Several tests below pin behaviour that is arguably wrong. They are marked
FALSE POSITIVE / MISLABELLED and exist so that the current behaviour is written down
and any change to it is deliberate rather than accidental. See "Known limitations" in
the README.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import monitor  # noqa: E402


def entry(reason="NotFilteredNotFound", rules=None):
    return {"reason": reason, "rules": rules or []}


# --- the cases the tool exists for ---------------------------------------------------


@pytest.mark.parametrize("reason", [
    "FilteredParental", "filteredparental", "FILTEREDPARENTAL",
])
def test_parental_reason_matches_regardless_of_case(reason):
    assert monitor.is_parental_block(entry(reason=reason)) is True


def test_adult_keyword_in_a_rule_matches():
    assert monitor.is_parental_block(entry("FilteredBlackList", [{"text": "||pornhub.com^"}])) is True
    assert monitor.is_parental_block(entry("FilteredBlackList", [{"text": "||xxx-tube.net^"}])) is True


def test_the_dedicated_adult_filter_list_matches_on_id_alone():
    """filter_list_id 1000001 is the adult list, so its rule text does not matter."""
    assert monitor.is_parental_block(entry("FilteredBlackList", [{"filter_list_id": 1000001}])) is True


def test_an_ordinary_allowed_query_does_not_match():
    assert monitor.is_parental_block(entry()) is False


def test_a_blocked_but_unrelated_domain_does_not_match():
    assert monitor.is_parental_block(entry("FilteredBlackList", [{"text": "||ads.example.com^"}])) is False


# --- shape robustness ----------------------------------------------------------------


def test_missing_keys_do_not_raise():
    assert monitor.is_parental_block({}) is False
    assert monitor.is_parental_block({"rules": [{}]}) is False


def test_a_non_string_rule_text_does_not_raise():
    """AdGuard has changed the query-log shape before; a number here must not crash."""
    assert monitor.is_parental_block(entry("FilteredBlackList", [{"text": 12345}])) is False


# --- behaviour that is pinned but questionable ---------------------------------------


@pytest.mark.parametrize("domain", [
    "||essex.ac.uk^",
    "||sussex.ac.uk^",
    "||middlesexhospital.org^",
])
def test_FALSE_POSITIVE_sex_matches_inside_innocent_words(domain):
    """The keyword "sex" is matched as a bare substring, so Essex, Sussex and
    Middlesex all raise "Adult Content Blocked".

    Pinned deliberately: this is a real false positive, and on a tool that tells a
    parent their child looked at adult content it is the expensive direction to get
    wrong. Changing it is a detection-policy decision, not a tidy-up.
    """
    assert monitor.is_parental_block(entry("FilteredBlackList", [{"text": domain}])) is True


def test_MISLABELLED_safebrowsing_is_reported_as_adult_content():
    """SafeBrowsing blocks malware and phishing, not adult content, but it is in
    PARENTAL_REASONS, so such a block is alerted under the title "Adult Content
    Blocked". The body does carry the real reason.
    """
    assert monitor.is_parental_block(entry(reason="FilteredSafeBrowsing")) is True
