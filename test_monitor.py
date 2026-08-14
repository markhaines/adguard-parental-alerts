import json
import os
import tempfile
import unittest
from unittest.mock import patch

import monitor


def make_entry(time, name, client="192.168.1.50", reason="FilteredParental",
               qtype="A", elapsed=1):
    return {
        "time": time, "client": client, "reason": reason, "elapsedMs": elapsed,
        "question": {"name": name, "type": qtype},
        "rules": [],
        "client_info": {"name": "kids-mac"},
    }


class FakeResponse:
    def __init__(self, page):
        self._page = page

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": self._page}


class FakeAdGuard:
    """Paginated stand-in for the AdGuard querylog API. log[0] is newest."""

    def __init__(self, log=None):
        self.log = list(log) if log else []
        self.auth = None
        self.verify = True
        self.pages_fetched = 0

    def get(self, url, params=None, timeout=None):
        self.pages_fetched += 1
        offset = params.get("offset", 0)
        limit = params.get("limit", monitor.QUERY_PAGE_SIZE)
        return FakeResponse(self.log[offset:offset + limit])

    def add_new(self, entry):
        self.log.insert(0, entry)


class ShiftingAdGuard(FakeAdGuard):
    """New queries arrive between page requests, so offset windows overlap."""

    def get(self, url, params=None, timeout=None):
        offset = params.get("offset", 0)
        limit = params.get("limit", monitor.QUERY_PAGE_SIZE)
        result = self.log[offset:offset + limit]
        self.pages_fetched += 1
        if self.pages_fetched == 1:
            self.log.insert(0, make_entry("2024-06-01T23:59:59.000Z", "shift.example",
                                          reason="NoSuchReason"))
        return FakeResponse(result)


def sent_messages(send_mock):
    return [call.args[1] for call in send_mock.call_args_list]


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        monitor.STATE_FILE = os.path.join(self.temp.name, "state.json")

    def tearDown(self):
        self.temp.cleanup()

    def test_rejected_notification_stays_pending(self):
        state = {"cursor": "cursor", "pending": [{"id": "1", "title": "t", "message": "m"}],
                 "initialised": True}
        with patch.object(monitor, "send_pushover", return_value=False):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)

    def test_accepted_notification_is_removed_and_persisted(self):
        state = {"cursor": "cursor", "pending": [{"id": "1", "title": "t", "message": "m"}],
                 "initialised": True}
        with patch.object(monitor, "send_pushover", return_value=True):
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"], [])

    def test_pushover_requires_success_body(self):
        from unittest.mock import Mock
        response = Mock(status_code=200)
        response.json.return_value = {"status": 0}
        with patch.object(monitor.requests, "post", return_value=response):
            self.assertFalse(monitor.send_pushover("t", "m"))


class ReliableDeliveryTests(unittest.TestCase):
    """Contract tests against a fake paginated AdGuard session."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        monitor.STATE_FILE = os.path.join(self.temp.name, "state.json")
        monitor.MAX_PENDING_ALERTS = 100

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, fake, state, deliver=False):
        patch_deliver = patch.object(monitor, "send_pushover", return_value=deliver)
        patch_session = patch.object(monitor.requests, "Session", return_value=fake)
        with patch_session, patch_deliver as send:
            monitor.check_adguard(state)
        return send

    def test_cursor_pages_across_multiple_pages(self):
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example")
               for m in range(220)]
        log[50] = make_entry("2024-06-01T00:50:00.000Z", "blocked.example")
        fake = FakeAdGuard(log)
        state = {"cursor": monitor.entry_id(log[-1]), "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertGreaterEqual(fake.pages_fetched, 3)
        self.assertEqual(state["cursor"], monitor.entry_id(log[0]))
        self.assertTrue(any("blocked.example" in m for m in sent_messages(send)))

    def test_lost_cursor_rebaselines_instead_of_wedging(self):
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example")
               for m in range(20)]
        log[5] = make_entry("2024-06-01T00:05:00.000Z", "lost-blocked.example")
        fake = FakeAdGuard(log)
        state = {"cursor": "2024-01-01T00:00:00.000Z|stale.example|1.2.3.4",
                 "pending": [], "initialised": True}
        with self.assertLogs(monitor.logger, level="WARNING") as captured:
            send = self.run_check(fake, state, deliver=True)
        self.assertTrue(any("re-baselin" in line for line in captured.output))
        self.assertEqual(state["cursor"], monitor.entry_id(log[0]))
        self.assertTrue(any("lost-blocked.example" in m for m in sent_messages(send)))

    def test_first_start_with_empty_log_then_first_batch_delivered(self):
        fake = FakeAdGuard([])
        state = monitor.load_state()
        send = self.run_check(fake, state, deliver=True)
        self.assertTrue(state["initialised"])
        self.assertIsNone(state["cursor"])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertTrue(json.load(state_file)["initialised"])

        fake.log.append(make_entry("2024-06-01T00:01:00.000Z", "blocked.example"))
        fake.log.append(make_entry("2024-06-01T00:00:00.000Z", "ok.example",
                                   reason="NoSuchReason"))
        send = self.run_check(fake, state, deliver=True)
        self.assertTrue(any("blocked.example" in m for m in sent_messages(send)))
        self.assertEqual(state["cursor"], monitor.entry_id(fake.log[0]))

    def test_duplicate_entry_produces_single_alert(self):
        blocked = make_entry("2024-06-01T00:00:00.000Z", "blocked.example")
        older = make_entry("2024-06-01T00:02:00.000Z", "ok.example", reason="NoSuchReason")
        log = [blocked, blocked, older]
        fake = FakeAdGuard(log)
        state = {"cursor": monitor.entry_id(older), "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len(send.call_args_list), 1)

    def test_pending_outbox_id_not_requeued(self):
        blocked = make_entry("2024-06-01T00:01:00.000Z", "blocked.example")
        older = make_entry("2024-06-01T00:00:00.000Z", "ok.example", reason="NoSuchReason")
        fake = FakeAdGuard([blocked, older])
        state = {"cursor": monitor.entry_id(older), "pending": [
            {"id": monitor.entry_id(blocked), "title": "Adult Content Blocked",
             "message": "queued"}], "initialised": True}
        send = self.run_check(fake, state, deliver=False)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(len(state["pending"]), 1)

    def test_overlapping_pages_produce_single_alert(self):
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example",
                          reason="FilteredParental" if m == 99 else "NoSuchReason")
               for m in range(250)]
        fake = ShiftingAdGuard(log)
        state = {"cursor": None, "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len(send.call_args_list), 1)
        self.assertEqual(state["cursor"], monitor.entry_id(log[0]))

    def test_state_persists_and_reloads_across_restart(self):
        blocked = make_entry("2024-06-01T00:01:00.000Z", "blocked.example")
        older = make_entry("2024-06-01T00:00:00.000Z", "ok.example", reason="NoSuchReason")
        fake = FakeAdGuard([blocked, older])
        state = {"cursor": None, "pending": [], "initialised": True}
        self.run_check(fake, state, deliver=False)

        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            persisted = json.load(state_file)
        self.assertEqual(len(persisted["pending"]), 1)
        self.assertEqual(persisted["cursor"], monitor.entry_id(blocked))
        self.assertTrue(persisted["initialised"])

        reloaded = monitor.load_state()
        self.assertEqual(reloaded["pending"], persisted["pending"])
        self.assertEqual(reloaded["cursor"], persisted["cursor"])
        self.assertTrue(reloaded["initialised"])

        new_blocked = make_entry("2024-06-01T00:02:00.000Z", "new-blocked.example")
        fake.add_new(new_blocked)
        self.run_check(fake, reloaded, deliver=False)
        ids = [a["id"] for a in reloaded["pending"]]
        self.assertEqual(ids.count(monitor.entry_id(new_blocked)), 1)
        self.assertEqual(ids.count(monitor.entry_id(blocked)), 1)

    def test_alert_that_fails_then_succeeds(self):
        state = {"cursor": "c", "pending": [{"id": "1", "title": "t", "message": "m"}],
                 "initialised": True}
        with patch.object(monitor, "send_pushover", return_value=False):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        with patch.object(monitor, "send_pushover", return_value=True):
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"], [])

    def test_failed_alert_does_not_block_later_alerts(self):
        state = {"cursor": "c", "pending": [
            {"id": "poison", "title": "t", "message": "poison"},
            {"id": "good", "title": "t2", "message": "good"},
        ], "initialised": True}
        with patch.object(monitor, "send_pushover", side_effect=[False, True]):
            monitor.deliver_pending(state)
        self.assertEqual([a["id"] for a in state["pending"]], ["poison"])

    def test_outbox_is_bounded(self):
        monitor.MAX_PENDING_ALERTS = 5
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example")
               for m in range(6)]
        fake = FakeAdGuard(log)
        state = {"cursor": None, "initialised": True,
                 "pending": [{"id": f"p{i}", "title": "t", "message": "m"}
                             for i in range(3)]}
        self.run_check(fake, state, deliver=False)
        self.assertLessEqual(len(state["pending"]), 5)

    def test_entry_id_distinguishes_otherwise_identical_queries(self):
        a = make_entry("2024-06-01T00:00:00.000Z", "same.example", qtype="A")
        b = make_entry("2024-06-01T00:00:00.000Z", "same.example", qtype="AAAA")
        c = make_entry("2024-06-01T00:00:00.000Z", "same.example", qtype="A", elapsed=7)
        self.assertNotEqual(monitor.entry_id(a), monitor.entry_id(b))
        self.assertNotEqual(monitor.entry_id(a), monitor.entry_id(c))


if __name__ == "__main__":
    unittest.main()
