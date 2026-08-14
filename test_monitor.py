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
        entry = {"reason": "FilteredBlackList", "rules": [{"filter_list_id": 42}]}
        self.assertTrue(monitor.is_parental_block(entry))

    def test_null_rules_do_not_abort_classification(self):
        self.assertFalse(monitor.is_parental_block({"reason": "FilteredBlackList", "rules": None}))


class AdultFilterIdsParsingTests(unittest.TestCase):
    def test_valid_list(self):
        self.assertEqual(monitor.parse_adult_filter_ids("42,43"), {42, 43})

    def test_whitespace_is_ignored(self):
        self.assertEqual(monitor.parse_adult_filter_ids("42, 43 "), {42, 43})

    def test_empty_or_unset_value(self):
        self.assertEqual(monitor.parse_adult_filter_ids(""), set())
        self.assertEqual(monitor.parse_adult_filter_ids(None), set())

    def test_duplicate_ids_are_deduplicated(self):
        self.assertEqual(monitor.parse_adult_filter_ids("42,42"), {42})

    def test_malformed_token_has_actionable_error(self):
        with self.assertRaisesRegex(
            ValueError,
            r"invalid ADULT_FILTER_IDS value 'abc'; expected comma-separated positive integers",
        ):
            monitor.parse_adult_filter_ids("42,abc")

    def test_non_positive_or_non_ascii_ids_are_rejected(self):
        for value in ("-5", "0", "+42", "٤٢"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "ADULT_FILTER_IDS"):
                    monitor.parse_adult_filter_ids(value)


class PollIntervalParsingTests(unittest.TestCase):
    def test_valid_or_unset_value(self):
        self.assertEqual(monitor.parse_poll_interval("30"), 30)
        self.assertEqual(monitor.parse_poll_interval(" 30 "), 30)
        self.assertEqual(monitor.parse_poll_interval(None), 60)

    def test_invalid_or_non_positive_value(self):
        for value in ("60s", "0", "-1", "+60", "٦٠", ""):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "POLL_INTERVAL"):
                    monitor.parse_poll_interval(value)


class MainConfigurationValidationTests(unittest.TestCase):
    required_configuration = {
        "ADGUARD_URL": "http://example.test",
        "ADGUARD_USERNAME": "user",
        "ADGUARD_PASSWORD": "password",
        "PUSHOVER_TOKEN": "token",
        "PUSHOVER_USER": "recipient",
    }

    def assert_main_configuration_error(self, environment, expected_message):
        patched_configuration = {
            **self.required_configuration,
            "ADULT_FILTER_IDS": set(),
            "POLL_INTERVAL": 60,
        }
        with mock.patch.multiple(monitor, **patched_configuration):
            with mock.patch.dict(monitor.os.environ, environment, clear=True):
                with self.assertLogs(monitor.logger, level="ERROR") as logs:
                    with self.assertRaises(SystemExit) as exit_context:
                        monitor.main()
        self.assertEqual(exit_context.exception.code, 1)
        self.assertIn("Invalid configuration:", "\n".join(logs.output))
        self.assertIn(expected_message, "\n".join(logs.output))

    def test_main_rejects_malformed_adult_filter_ids(self):
        self.assert_main_configuration_error(
            {"POLL_INTERVAL": "60", "ADULT_FILTER_IDS": "42,abc"},
            "invalid ADULT_FILTER_IDS value 'abc'",
        )

    def test_main_rejects_malformed_poll_interval(self):
        self.assert_main_configuration_error(
            {"POLL_INTERVAL": "60s", "ADULT_FILTER_IDS": "42"},
            "invalid POLL_INTERVAL value '60s'",
        )


if __name__ == "__main__":
    unittest.main()
