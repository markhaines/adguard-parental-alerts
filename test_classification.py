import unittest
from unittest import mock

import monitor


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.original_ids = monitor.ADULT_FILTER_IDS
        monitor.ADULT_FILTER_IDS = set()

    def tearDown(self):
        monitor.ADULT_FILTER_IDS = self.original_ids

    def test_parental_reason_matches(self):
        self.assertTrue(monitor.is_parental_block({"reason": "FilteredParental"}))

    def test_parental_reason_requires_exact_case_sensitive_match(self):
        for reason in ("filteredparental", "FilteredParentalExtra", "Parental"):
            with self.subTest(reason=reason):
                self.assertFalse(monitor.is_parental_block({"reason": reason}))

    def test_safe_browsing_is_not_adult_content(self):
        self.assertFalse(monitor.is_parental_block({"reason": "FilteredSafeBrowsing"}))

    def test_innocent_rule_substrings_do_not_match(self):
        entry = {"reason": "FilteredBlackList", "rules": [{"text": "||essex.example^"}]}
        self.assertFalse(monitor.is_parental_block(entry))

    def test_configured_filter_id_matches(self):
        monitor.ADULT_FILTER_IDS = {42}
        self.assertTrue(monitor.is_parental_block(
            {"reason": "FilteredBlackList", "rules": [{"filter_list_id": 42}]}))

    def test_filter_id_zero_matches_only_blacklist_reason(self):
        monitor.ADULT_FILTER_IDS = {0}
        self.assertTrue(monitor.is_parental_block(
            {"reason": "FilteredBlackList", "rules": [{"filter_list_id": 0}]}))
        for reason in ("Rewrite", "NotFiltered", "FilteredSafeBrowsing"):
            self.assertFalse(monitor.is_parental_block(
                {"reason": reason, "rules": [{"filter_list_id": 0}]}))

    def test_null_rules_do_not_abort_classification(self):
        self.assertFalse(monitor.is_parental_block({"reason": "FilteredBlackList", "rules": None}))


class AdultFilterIdsParsingTests(unittest.TestCase):
    def test_valid_list(self):
        self.assertEqual(monitor.parse_adult_filter_ids("42,43"), {42, 43})

    def test_zero_is_valid(self):
        self.assertEqual(monitor.parse_adult_filter_ids("0"), {0})

    def test_whitespace_and_duplicates(self):
        self.assertEqual(monitor.parse_adult_filter_ids("42, 43,42 "), {42, 43})

    def test_empty_or_unset(self):
        self.assertEqual(monitor.parse_adult_filter_ids(""), set())
        self.assertEqual(monitor.parse_adult_filter_ids(None), set())

    def test_malformed_token_is_actionable(self):
        with self.assertRaisesRegex(ValueError, "invalid ADULT_FILTER_IDS value 'abc'"):
            monitor.parse_adult_filter_ids("42,abc")

    def test_negative_signed_or_unicode_ids_are_rejected(self):
        for value in ("-5", "+42", "٤٢"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "ADULT_FILTER_IDS"):
                monitor.parse_adult_filter_ids(value)


class PollIntervalParsingTests(unittest.TestCase):
    def test_valid_or_unset(self):
        self.assertEqual(monitor.parse_poll_interval("30"), 30)
        self.assertEqual(monitor.parse_poll_interval(" 30 "), 30)
        self.assertEqual(monitor.parse_poll_interval(None), 60)

    def test_invalid_nonpositive_or_over_cap(self):
        for value in ("60s", "0", "-1", "+60", "٦٠", "", "86401"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "POLL_INTERVAL"):
                monitor.parse_poll_interval(value)


class MainConfigurationValidationTests(unittest.TestCase):
    required = dict(ADGUARD_URL="http://example.test", ADGUARD_USERNAME="user",
                    ADGUARD_PASSWORD="password", PUSHOVER_TOKEN="token", PUSHOVER_USER="recipient")

    def assert_config_error(self, environment, expected):
        with mock.patch.multiple(monitor, **self.required), \
                mock.patch.dict(monitor.os.environ, environment, clear=True), \
                self.assertLogs(monitor.logger, level="ERROR") as logs, \
                self.assertRaises(SystemExit) as raised:
            monitor.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn(expected, "\n".join(logs.output))

    def test_main_rejects_malformed_filter_ids(self):
        self.assert_config_error({"POLL_INTERVAL": "60", "ADULT_FILTER_IDS": "42,abc"},
                                 "invalid ADULT_FILTER_IDS value 'abc'")

    def test_main_rejects_malformed_poll_interval(self):
        self.assert_config_error({"POLL_INTERVAL": "60s", "ADULT_FILTER_IDS": "42"},
                                 "invalid POLL_INTERVAL value '60s'")

    def test_valid_configuration_updates_globals(self):
        with mock.patch.multiple(monitor, ADULT_FILTER_IDS=set(), POLL_INTERVAL=60), \
                mock.patch.dict(monitor.os.environ,
                                {"POLL_INTERVAL": "30", "ADULT_FILTER_IDS": "0,42"}, clear=True):
            monitor.validate_configuration()
            self.assertEqual(monitor.POLL_INTERVAL, 30)
            self.assertEqual(monitor.ADULT_FILTER_IDS, {0, 42})


if __name__ == "__main__":
    unittest.main()
