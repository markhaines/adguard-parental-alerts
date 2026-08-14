import unittest

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
            r"invalid ADULT_FILTER_IDS value 'abc'; expected comma-separated integers",
        ):
            monitor.parse_adult_filter_ids("42,abc")


if __name__ == "__main__":
    unittest.main()
