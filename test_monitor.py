import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import monitor


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        monitor.STATE_FILE = os.path.join(self.temp.name, "state.json")

    def tearDown(self):
        self.temp.cleanup()

    def test_rejected_notification_stays_pending(self):
        state = {"cursor": "cursor", "pending": [{"id": "1", "title": "t", "message": "m"}]}
        with patch.object(monitor, "send_pushover", return_value=False):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)

    def test_accepted_notification_is_removed_and_persisted(self):
        state = {"cursor": "cursor", "pending": [{"id": "1", "title": "t", "message": "m"}]}
        with patch.object(monitor, "send_pushover", return_value=True):
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"], [])

    def test_pushover_requires_success_body(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 0}
        with patch.object(monitor.requests, "post", return_value=response):
            self.assertFalse(monitor.send_pushover("t", "m"))


if __name__ == "__main__":
    unittest.main()
