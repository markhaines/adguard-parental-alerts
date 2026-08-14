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

    def test_safe_browsing_is_not_adult_content(self):
        self.assertFalse(monitor.is_parental_block({"reason": "FilteredSafeBrowsing"}))

    def test_innocent_rule_substrings_do_not_match(self):
        entry = {"reason": "FilteredBlackList", "rules": [{"text": "||essex.example^"}]}
        self.assertFalse(monitor.is_parental_block(entry))

    def test_configured_filter_id_matches(self):
        monitor.ADULT_FILTER_IDS = {42}
        entry = {"reason": "FilteredBlackList", "rules": [{"filter_list_id": 42}]}
        self.assertTrue(monitor.is_parental_block(entry))


if __name__ == "__main__":
    unittest.main()
