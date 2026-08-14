import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import monitor


def make_entry(time, name, client="192.168.1.50", reason="FilteredParental",
               qtype="A"):
    return {
        "time": time, "client": client, "reason": reason,
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


class LiveLogAdGuard(FakeAdGuard):
    """The log grows while pages are served: fresh (non-parental) queries
    arrive before each page request, shifting the offset window so pages
    overlap and a cursor near a page boundary is displaced into the next
    page."""

    def __init__(self, initial=None, arrivals=()):
        super().__init__(initial)
        self.arrivals = list(arrivals)
        self._next_arrival = 0
        self.page0_head = None

    def get(self, url, params=None, timeout=None):
        if self._next_arrival < len(self.arrivals):
            self.log.insert(0, self.arrivals[self._next_arrival])
            self._next_arrival += 1
        if self.page0_head is None and self.log:
            self.page0_head = self.log[0]
        offset = params.get("offset", 0)
        limit = params.get("limit", monitor.QUERY_PAGE_SIZE)
        page = self.log[offset:offset + limit]
        self.pages_fetched += 1
        return FakeResponse(page)


def sent_messages(send_mock):
    return [call.args[1] for call in send_mock.call_args_list]


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        monitor.STATE_FILE = os.path.join(self.temp.name, "state.json")
        monitor._last_notice.clear()

    def tearDown(self):
        self.temp.cleanup()

    def test_rejected_notification_stays_pending(self):
        state = {"cursor": "cursor", "pending": [{"id": "1", "title": "t", "message": "m"}],
                 "initialised": True}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_TRANSIENT):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)

    def test_accepted_notification_is_removed_and_persisted(self):
        state = {"cursor": "cursor", "pending": [{"id": "1", "title": "t", "message": "m"}],
                 "initialised": True}
        with patch.object(monitor, "send_pushover", return_value=monitor.DELIVERY_OK):
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"], [])

    def test_pushover_requires_success_body(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": 0}
        with patch.object(monitor.requests, "post", return_value=response):
            self.assertEqual(monitor.send_pushover("t", "m"), monitor.DELIVERY_TRANSIENT)


class ReliableDeliveryTests(unittest.TestCase):
    """Contract tests against a fake paginated AdGuard session."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        monitor.STATE_FILE = os.path.join(self.temp.name, "state.json")
        monitor.MAX_PENDING_ALERTS = 100
        monitor.MAX_ALERT_ATTEMPTS = 5
        monitor.ALERT_BACKOFF_BASE = 60
        monitor._last_notice.clear()

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, fake, state, deliver=False):
        result = monitor.DELIVERY_OK if deliver else monitor.DELIVERY_TRANSIENT
        patch_deliver = patch.object(monitor, "send_pushover", return_value=result)
        patch_session = patch.object(monitor.requests, "Session", return_value=fake)
        with patch_session, patch_deliver as send:
            monitor.check_adguard(state)
        return send

    def test_cursor_pages_across_multiple_pages(self):
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example",
                          reason="NoSuchReason") for m in range(220)]
        log[50] = make_entry("2024-06-01T00:50:00.000Z", "blocked.example")
        fake = FakeAdGuard(log)
        state = {"version": 2, "cursor": monitor.entry_id(log[-1]),
                 "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertGreaterEqual(fake.pages_fetched, 3)
        self.assertEqual(state["cursor"], monitor.entry_id(log[0]))
        self.assertTrue(any("blocked.example" in m for m in sent_messages(send)))

    def test_lost_cursor_rebaselines_and_notifies_operator(self):
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example",
                          reason="NoSuchReason") for m in range(20)]
        log[5] = make_entry("2024-06-01T00:05:00.000Z", "lost-blocked.example")
        fake = FakeAdGuard(log)
        state = {"version": 2, "cursor": "2024-01-01T00:00:00.000Z|stale.example|1.2.3.4",
                 "pending": [], "initialised": True}
        with self.assertLogs(monitor.logger, level="WARNING") as captured:
            send = self.run_check(fake, state, deliver=True)
        self.assertTrue(any("re-baselin" in line for line in captured.output))
        self.assertEqual(state["cursor"], monitor.entry_id(log[0]))
        self.assertTrue(any("lost-blocked.example" in m for m in sent_messages(send)))
        self.assertTrue(any("may have been missed" in m for m in sent_messages(send)))

    def test_loss_notices_are_cooldown_suppressed(self):
        fake = FakeAdGuard([])
        state = {"version": 2, "cursor": "stale", "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len([m for m in sent_messages(send) if "may have been missed" in m]), 1)
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len([m for m in sent_messages(send) if "may have been missed" in m]), 0)

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
        state = {"version": 2, "cursor": monitor.entry_id(older),
                 "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len(send.call_args_list), 1)

    def test_pending_outbox_id_not_requeued(self):
        blocked = make_entry("2024-06-01T00:01:00.000Z", "blocked.example")
        older = make_entry("2024-06-01T00:00:00.000Z", "ok.example", reason="NoSuchReason")
        fake = FakeAdGuard([blocked, older])
        state = {"version": 2, "cursor": monitor.entry_id(older), "pending": [
            {"id": monitor.entry_id(blocked), "title": "Adult Content Blocked",
             "message": "queued"}], "initialised": True}
        send = self.run_check(fake, state, deliver=False)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(len(state["pending"]), 1)

    def test_overlapping_pages_produce_single_alert(self):
        base = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example",
                           reason="FilteredParental" if m == 98 else "NoSuchReason")
                for m in range(250)]
        arrivals = [make_entry(f"2024-06-01T00:00:0{i}.500Z", f"arrival{i}.example",
                               reason="NoSuchReason") for i in range(3)]
        fake = LiveLogAdGuard(base, arrivals)
        state = {"version": 2, "cursor": None, "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len(send.call_args_list), 1)
        self.assertEqual(state["cursor"], monitor.entry_id(fake.page0_head))
        self.assertEqual(fake.log[0]["question"]["name"], "arrival2.example")

    def test_cursor_survives_multiple_arrivals_and_page_displacement(self):
        base = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example",
                           reason="FilteredParental" if m == 50 else "NoSuchReason")
                for m in range(230)]
        arrivals = [make_entry(f"2024-06-01T00:00:0{i}.500Z", f"arrival{i}.example",
                               reason="NoSuchReason") for i in range(15)]
        fake = LiveLogAdGuard(base, arrivals)
        state = {"version": 2, "cursor": monitor.entry_id(base[99]),
                 "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertTrue(any("d50.example" in m for m in sent_messages(send)))
        self.assertGreaterEqual(fake.pages_fetched, 2)
        self.assertEqual(state["cursor"], monitor.entry_id(fake.page0_head))
        self.assertEqual(fake.log[0]["question"]["name"], "arrival1.example")

    def test_state_persists_and_reloads_across_restart(self):
        blocked = make_entry("2024-06-01T00:01:00.000Z", "blocked.example")
        older = make_entry("2024-06-01T00:00:00.000Z", "ok.example", reason="NoSuchReason")
        fake = FakeAdGuard([blocked, older])
        state = {"version": 2, "cursor": None, "pending": [], "initialised": True}
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
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "1", "title": "t", "message": "m"}]}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_TRANSIENT):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        state["pending"][0]["next_attempt"] = 0
        with patch.object(monitor, "send_pushover", return_value=monitor.DELIVERY_OK):
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"], [])

    def test_failed_alert_does_not_block_later_alerts(self):
        state = {"version": 2, "cursor": "c", "initialised": True, "pending": [
            {"id": "poison", "title": "t", "message": "poison"},
            {"id": "good", "title": "t2", "message": "good"},
        ]}
        with patch.object(monitor, "send_pushover", side_effect=[
                monitor.DELIVERY_TRANSIENT, monitor.DELIVERY_OK]):
            monitor.deliver_pending(state)
        self.assertEqual([a["id"] for a in state["pending"]], ["poison"])

    def test_retry_backoff_defers_next_attempt(self):
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "x", "title": "t", "message": "m"}]}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_TRANSIENT) as send:
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        self.assertIn("next_attempt", state["pending"][0])
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_OK) as send2:
            monitor.deliver_pending(state)
        self.assertEqual(send2.call_count, 0)
        future = monitor.time.time() + monitor.ALERT_BACKOFF_BASE + 1
        with patch.object(monitor.time, "time", return_value=future):
            with patch.object(monitor, "send_pushover",
                              return_value=monitor.DELIVERY_OK) as send3:
                monitor.deliver_pending(state)
        self.assertEqual(send3.call_count, 1)
        self.assertEqual(state["pending"], [])

    def test_permanent_rejection_drops_alert_and_notifies(self):
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "bad", "title": "t", "message": "m"}]}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_PERMANENT) as send:
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        self.assertTrue(any(call.args[0] == "Alert dropped: Pushover rejected it"
                            for call in send.call_args_list))

    def test_attempts_exhausted_drops_alert_and_notifies(self):
        monitor.MAX_ALERT_ATTEMPTS = 2
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "x", "title": "t", "message": "m", "attempts": 1}]}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_TRANSIENT) as send:
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])
        self.assertTrue(any(call.args[0] == "Alert dropped: delivery retries exhausted"
                            for call in send.call_args_list))

    def test_outbox_is_bounded_and_notifies(self):
        monitor.MAX_PENDING_ALERTS = 5
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example")
               for m in range(6)]
        fake = FakeAdGuard(log)
        state = {"version": 2, "cursor": None, "initialised": True,
                 "pending": [{"id": f"p{i}", "title": "t", "message": "m"}
                             for i in range(3)]}
        send = self.run_check(fake, state, deliver=False)
        self.assertLessEqual(len(state["pending"]), 5)
        self.assertEqual(state["pending"][0]["id"], "p0")
        self.assertTrue(any(call.args[0] == "AdGuard alerts dropped"
                            for call in send.call_args_list))

    def test_send_pushover_classifies_failures(self):
        for status, expected in [(200, monitor.DELIVERY_OK),
                                 (400, monitor.DELIVERY_PERMANENT),
                                 (429, monitor.DELIVERY_TRANSIENT),
                                 (500, monitor.DELIVERY_TRANSIENT)]:
            response = Mock(status_code=status)
            response.json.return_value = {"status": 1}
            with patch.object(monitor.requests, "post", return_value=response):
                self.assertEqual(monitor.send_pushover("t", "m"), expected, status)
        with patch.object(monitor.requests, "post", side_effect=OSError("boom")):
            self.assertEqual(monitor.send_pushover("t", "m"), monitor.DELIVERY_TRANSIENT)

    def test_entry_id_uses_immutable_fields_only(self):
        a = make_entry("2024-06-01T00:00:00.000Z", "same.example", qtype="A")
        b = make_entry("2024-06-01T00:00:00.000Z", "same.example", qtype="AAAA")
        a_elapsed = dict(a, elapsedMs=999)
        self.assertNotEqual(monitor.entry_id(a), monitor.entry_id(b))
        self.assertEqual(monitor.entry_id(a), monitor.entry_id(a_elapsed))

    def test_legacy_state_files_migrate_safely(self):
        with open(monitor.STATE_FILE, "w", encoding="utf-8") as state_file:
            json.dump({"cursor": None, "pending": [], "initialised": True}, state_file)
        state = monitor.load_state()
        self.assertTrue(state["initialised"])
        self.assertEqual(state["version"], 2)

        with open(monitor.STATE_FILE, "w", encoding="utf-8") as state_file:
            json.dump({"cursor": "c|d|1", "pending": []}, state_file)
        state = monitor.load_state()
        self.assertTrue(state["initialised"])
        self.assertEqual(state["cursor"], "c|d|1")

        os.remove(monitor.STATE_FILE)
        state = monitor.load_state()
        self.assertFalse(state["initialised"])
        self.assertEqual(state["version"], 2)

    def test_save_state_writes_schema_version(self):
        monitor.save_state({"cursor": None, "pending": [], "initialised": True})
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["version"], 2)


if __name__ == "__main__":
    unittest.main()
