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

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, fake, state, deliver=False):
        result = monitor.DELIVERY_OK if deliver else monitor.DELIVERY_TRANSIENT
        patch_deliver = patch.object(monitor, "send_pushover", return_value=result)
        patch_session = patch.object(monitor.requests, "Session", return_value=fake)
        with patch_session, patch_deliver as send:
            monitor.check_adguard(state)
        return send

    def test_persistence_failure_does_not_prevent_delivery_attempt(self):
        entry = make_entry("2024-06-01T00:01:00.000Z", "blocked.example")
        state = {"version": 2, "cursor": None, "pending": [], "initialised": True}
        with patch.object(monitor.requests, "Session", return_value=FakeAdGuard([entry])), \
                patch.object(monitor, "save_state", side_effect=OSError("disk full")), \
                patch.object(monitor, "deliver_pending") as deliver:
            persistence_ok = monitor.check_adguard(state)
        self.assertFalse(persistence_ok)
        deliver.assert_called_once_with(state)

    def test_three_consecutive_persistence_failures_exit_nonzero(self):
        state = {"version": 2, "cursor": None, "pending": [], "initialised": True}
        required = dict(ADGUARD_URL="http://example.test", ADGUARD_USERNAME="user",
                        ADGUARD_PASSWORD="password", PUSHOVER_TOKEN="token",
                        PUSHOVER_USER="recipient")
        with patch.multiple(monitor, **required), \
                patch.dict(monitor.os.environ, {}, clear=True), \
                patch.object(monitor, "send_pushover", return_value=monitor.DELIVERY_OK), \
                patch.object(monitor, "load_state", return_value=state), \
                patch.object(monitor, "check_adguard", side_effect=[False, False, False]) as check, \
                patch.object(monitor.time, "sleep"):
            with self.assertRaises(SystemExit) as raised:
                monitor.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(check.call_count, monitor.MAX_CONSECUTIVE_PERSISTENCE_FAILURES)

    def test_successful_poll_resets_persistence_failure_counter(self):
        state = {"version": 2, "cursor": None, "pending": [], "initialised": True}
        required = dict(ADGUARD_URL="http://example.test", ADGUARD_USERNAME="user",
                        ADGUARD_PASSWORD="password", PUSHOVER_TOKEN="token",
                        PUSHOVER_USER="recipient")
        with patch.multiple(monitor, **required), \
                patch.dict(monitor.os.environ, {}, clear=True), \
                patch.object(monitor, "send_pushover", return_value=monitor.DELIVERY_OK), \
                patch.object(monitor, "load_state", return_value=state), \
                patch.object(monitor, "check_adguard",
                             side_effect=[False, False, True, False, False, KeyboardInterrupt]), \
                patch.object(monitor.time, "sleep"):
            with self.assertRaises(KeyboardInterrupt):
                monitor.main()

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

    def test_recurring_loss_aggregates_notice_count(self):
        fake = FakeAdGuard([])
        state = {"version": 2, "cursor": "stale", "pending": [], "initialised": True}
        self.run_check(fake, state, deliver=False)
        self.run_check(fake, state, deliver=False)
        notices = [a for a in state["pending"] if a.get("kind") == "notice"]
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["name"], "cursor-gap")
        self.assertEqual(notices[0]["count"], 2)
        self.assertIn("Occurrences: 2", notices[0]["message"])

    def test_recurrence_after_delivery_is_not_suppressed(self):
        fake = FakeAdGuard([])
        state = {"version": 2, "cursor": "stale", "pending": [], "initialised": True}
        send = self.run_check(fake, state, deliver=True)
        self.assertEqual(len([m for m in sent_messages(send) if "may have been missed" in m]), 1)
        send2 = self.run_check(fake, state, deliver=True)
        self.assertEqual(len([m for m in sent_messages(send2) if "may have been missed" in m]), 1)
        self.assertEqual(state["pending"], [])

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

    def test_permanent_rejection_drops_alert_and_queues_notice(self):
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "bad", "title": "t", "message": "m"}]}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_PERMANENT):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["kind"], "notice")
        self.assertEqual(state["pending"][0]["count"], 1)
        self.assertEqual(state["pending"][0]["title"], "Alert dropped: Pushover rejected it")
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"][0]["kind"], "notice")

    def test_attempts_exhausted_drops_alert_and_queues_notice(self):
        monitor.MAX_ALERT_ATTEMPTS = 2
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "x", "title": "t", "message": "m", "attempts": 1}]}
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_TRANSIENT):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["kind"], "notice")
        self.assertEqual(state["pending"][0]["count"], 1)
        self.assertEqual(state["pending"][0]["title"],
                         "Alert dropped: delivery retries exhausted")

    def test_outbox_keeps_newest_and_queues_notice_with_window(self):
        monitor.MAX_PENDING_ALERTS = 5
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example")
               for m in range(6)]
        fake = FakeAdGuard(log)
        state = {"version": 2, "cursor": None, "initialised": True,
                 "pending": [{"id": f"p{i}", "title": "t", "message": "m",
                              "ts": f"2024-06-01T00:10:0{i}.000Z"}
                             for i in range(3)]}
        send = self.run_check(fake, state, deliver=False)
        self.assertLessEqual(len(state["pending"]), 6)
        notice = [a for a in state["pending"] if a.get("kind") == "notice"]
        self.assertEqual(len(notice), 1)
        self.assertIn("4 undelivered alerts were dropped", notice[0]["message"])
        self.assertIn("Affected time window:", notice[0]["message"])
        self.assertIn("2024-06-01T00:10:00.000Z", notice[0]["message"])
        alert_ids = [a["id"] for a in state["pending"] if a.get("kind") != "notice"]
        self.assertEqual(len(alert_ids), 5)
        self.assertNotIn("p0", alert_ids)
        self.assertNotIn("p1", alert_ids)
        self.assertIn(monitor.entry_id(log[0]), alert_ids)

    def test_notices_survive_overflow_trim(self):
        monitor.MAX_PENDING_ALERTS = 5
        log = [make_entry(f"2024-06-01T00:{m:02d}:00.000Z", f"d{m}.example")
               for m in range(8)]
        fake = FakeAdGuard(log)
        state = {"version": 2, "cursor": None, "initialised": True,
                 "pending": [{"id": "notice:cursor-gap:1", "kind": "notice",
                              "name": "cursor-gap", "title": "gap", "message": "gap",
                              "count": 1, "ts": 1.0,
                              "window_start": 1.0, "window_end": 1.0}]}
        self.run_check(fake, state, deliver=False)
        kinds = [a.get("kind") for a in state["pending"]]
        self.assertEqual(kinds.count("notice"), 2)
        self.assertEqual(len([a for a in state["pending"] if a.get("kind") == "notice"]), 2)
        self.assertLessEqual(len(state["pending"]), 7)

    def test_send_pushover_classifies_failures(self):
        for status, expected in [(200, monitor.DELIVERY_OK),
                                 (400, monitor.DELIVERY_PERMANENT),
                                 (401, monitor.DELIVERY_CONFIG),
                                 (404, monitor.DELIVERY_CONFIG),
                                 (408, monitor.DELIVERY_TRANSIENT),
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
        # Pre-version state files were only ever written after a baseline was
        # established (the cursor is set on every save), so an unversioned file
        # always carried a cursor. Reflect that reality, not cursor=None.
        with open(monitor.STATE_FILE, "w", encoding="utf-8") as state_file:
            json.dump({"cursor": "c|d|1", "pending": [], "initialised": True}, state_file)
        state = monitor.load_state()
        self.assertTrue(state["initialised"])
        self.assertEqual(state["cursor"], "c|d|1")
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

    def test_config_fault_keeps_alerts_queued(self):
        monitor.MAX_ALERT_ATTEMPTS = 1
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "x", "title": "t", "message": "m", "attempts": 1}]}
        with patch.object(monitor, "send_pushover", return_value=monitor.DELIVERY_CONFIG):
            monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["id"], "x")
        self.assertIn("next_attempt", state["pending"][0])
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["pending"][0]["id"], "x")

    def test_crash_mid_batch_loses_at_most_one_batch_of_progress(self):
        monitor.STATE_SAVE_INTERVAL = 2
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "a", "title": "t", "message": "m"},
                             {"id": "b", "title": "t2", "message": "m2"},
                             {"id": "c", "title": "t3", "message": "m3"}]}
        with patch.object(monitor, "send_pushover", side_effect=[
                monitor.DELIVERY_TRANSIENT, monitor.DELIVERY_TRANSIENT,
                OSError("crash")]):
            with self.assertRaises(OSError):
                monitor.deliver_pending(state)
        self.assertEqual(state["pending"][0]["id"], "a")
        self.assertEqual(state["pending"][0]["attempts"], 1)
        self.assertEqual(state["pending"][1]["id"], "b")
        self.assertEqual(state["pending"][1]["attempts"], 1)
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            persisted = json.load(state_file)
        self.assertEqual(persisted["pending"][0]["attempts"], 1)
        self.assertEqual(persisted["pending"][1]["attempts"], 1)
        self.assertEqual(persisted["pending"][2]["id"], "c")
        self.assertNotIn("attempts", persisted["pending"][2])

    def test_notice_survives_restart_and_is_delivered(self):
        fake = FakeAdGuard([])
        state = {"version": 2, "cursor": "stale", "pending": [], "initialised": True}
        self.run_check(fake, state, deliver=False)
        self.assertEqual(state["pending"][0]["kind"], "notice")
        reloaded = monitor.load_state()
        self.assertEqual(reloaded["pending"][0]["kind"], "notice")
        reloaded["pending"][0]["next_attempt"] = 0
        with patch.object(monitor, "send_pushover", return_value=monitor.DELIVERY_OK) as send:
            monitor.deliver_pending(reloaded)
        self.assertEqual(reloaded["pending"], [])
        self.assertTrue(any("may have been missed" in m for m in sent_messages(send)))

    def test_notice_queued_mid_pass_does_not_reprocess_alert(self):
        state = {"version": 2, "cursor": "c", "initialised": True,
                 "pending": [{"id": "a", "title": "t", "message": "m"},
                             {"id": "b", "title": "t2", "message": "m2"},
                             {"id": "c", "title": "t3", "message": "m3"}]}
        calls = {"n": 0}
        def flaky(title, message):
            calls["n"] += 1
            if calls["n"] == 1:
                return monitor.DELIVERY_PERMANENT
            return monitor.DELIVERY_OK
        with patch.object(monitor, "send_pushover", side_effect=flaky):
            monitor.deliver_pending(state)
        self.assertEqual(calls["n"], 3)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["kind"], "notice")
        self.assertEqual(state["pending"][0]["name"], "permanent-reject")

    def test_notice_survives_repeated_failures_without_dropping(self):
        monitor.ALERT_BACKOFF_BASE = 0
        state = {"version": 2, "cursor": "stale", "initialised": True,
                 "pending": [{"id": "n", "kind": "notice", "name": "cursor-gap",
                              "title": "t", "message": "m", "count": 1,
                              "ts": 0.0, "window_start": 0.0, "window_end": 0.0}]}
        for i in range(12):
            with patch.object(monitor, "send_pushover",
                              return_value=monitor.DELIVERY_TRANSIENT):
                monitor.deliver_pending(state)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["id"], "n")
        self.assertEqual(state["pending"][0]["attempts"], 12)
        with patch.object(monitor, "send_pushover",
                          return_value=monitor.DELIVERY_OK):
            monitor.deliver_pending(state)
        self.assertEqual(state["pending"], [])

    def test_save_state_writes_schema_version(self):
        monitor.save_state({"cursor": None, "pending": [], "initialised": True})
        with open(monitor.STATE_FILE, encoding="utf-8") as state_file:
            self.assertEqual(json.load(state_file)["version"], 2)


if __name__ == "__main__":
    unittest.main()
