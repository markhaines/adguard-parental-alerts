import unittest
import tempfile
from unittest.mock import Mock, patch

import monitor


class TlsTests(unittest.TestCase):
    def setUp(self):
        self.tls_config = patch.multiple(
            monitor, VERIFY_TLS=True, VERIFY_TLS_SETTING="true",
            ADGUARD_CA_BUNDLE="")
        self.tls_config.start()
        self.addCleanup(self.tls_config.stop)

    def session(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200)
        session.get.return_value.json.return_value = {"data": []}
        return session

    def test_tls_verification_is_enabled_by_default(self):
        session = self.session()
        with patch.object(monitor.requests, "Session", return_value=session):
            monitor.check_adguard()
        self.assertIs(session.verify, True)

    def test_custom_ca_bundle_is_used(self):
        session = self.session()
        with patch.object(monitor, "ADGUARD_CA_BUNDLE", "/ca/private.pem"), \
                patch.object(monitor.requests, "Session", return_value=session):
            monitor.check_adguard()
        self.assertEqual(session.verify, "/ca/private.pem")

    def test_tls_verification_can_be_explicitly_disabled(self):
        session = self.session()
        with patch.multiple(monitor, VERIFY_TLS=False,
                ADGUARD_CA_BUNDLE="/stale/unused.pem"), \
                patch.object(monitor.requests, "Session", return_value=session):
            monitor.check_adguard()
        self.assertIs(session.verify, False)

    def test_tls_verification_setting_fails_closed(self):
        for value in ("", "garbage", "1"):
            with self.subTest(value=value):
                self.assertTrue(monitor.tls_verification_enabled(value))

    def test_only_explicit_false_values_disable_tls_verification(self):
        for value in ("0", "false", "no", " false "):
            with self.subTest(value=value):
                self.assertFalse(monitor.tls_verification_enabled(value))

    def test_noncanonical_tls_values_are_unknown(self):
        for value in ("off", "OFF", "falsse", "garbage", ""):
            with self.subTest(value=value):
                self.assertFalse(monitor.tls_verification_setting_known(value))


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.network_guard = patch.object(
            monitor.requests, "post",
            side_effect=AssertionError("tests must not make network calls"))
        self.network_guard.start()
        self.addCleanup(self.network_guard.stop)

    def test_unreadable_ca_bundle_exits_at_startup(self):
        ca_path = "/nonexistent/ca.pem"
        with patch.multiple(monitor,
                ADGUARD_URL="https://adguard.example",
                ADGUARD_USERNAME="user",
                ADGUARD_PASSWORD="password",
                PUSHOVER_TOKEN="token",
                PUSHOVER_USER="user-key",
                ADGUARD_CA_BUNDLE=ca_path), \
                patch.object(monitor.logger, "error") as error, \
                patch.object(monitor, "send_pushover"), \
                patch.object(monitor, "check_adguard",
                    side_effect=AssertionError("entered poll loop")):
            with self.assertRaises(SystemExit) as raised:
                monitor.main()
        self.assertEqual(raised.exception.code, 1)
        error.assert_called_once()
        self.assertIn(ca_path, error.call_args.args[0])

    def test_empty_ca_bundle_exits_at_startup(self):
        self.assert_invalid_ca_bundle("")

    def test_garbage_ca_bundle_exits_at_startup(self):
        self.assert_invalid_ca_bundle("not a PEM certificate")

    def assert_invalid_ca_bundle(self, contents):
        with tempfile.NamedTemporaryFile(mode="w") as ca_bundle:
            ca_bundle.write(contents)
            ca_bundle.flush()
            with patch.multiple(monitor,
                    ADGUARD_URL="https://adguard.example",
                    ADGUARD_USERNAME="user",
                    ADGUARD_PASSWORD="password",
                    PUSHOVER_TOKEN="token",
                    PUSHOVER_USER="user-key",
                    ADGUARD_CA_BUNDLE=ca_bundle.name,
                    VERIFY_TLS=True,
                    VERIFY_TLS_SETTING="true"), \
                    patch.object(monitor.logger, "error") as error, \
                    patch.object(monitor, "send_pushover"), \
                    patch.object(monitor, "check_adguard",
                        side_effect=AssertionError("entered poll loop")):
                with self.assertRaises(SystemExit) as raised:
                    monitor.main()
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("not a valid PEM", error.call_args.args[0])

    def test_disabled_verification_logs_startup_warning(self):
        with patch.multiple(monitor,
                ADGUARD_URL="https://adguard.example",
                ADGUARD_USERNAME="user",
                ADGUARD_PASSWORD="password",
                PUSHOVER_TOKEN="token",
                PUSHOVER_USER="user-key",
                ADGUARD_CA_BUNDLE="/stale/unused.pem",
                VERIFY_TLS=False), \
                patch.object(monitor.logger, "warning") as warning, \
                patch.object(monitor, "send_pushover"), \
                patch.object(monitor, "check_adguard", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                monitor.main()
        warning.assert_called_once()
        self.assertIn("DISABLED", warning.call_args.args[0])

    def test_unrecognized_verification_setting_logs_warning(self):
        with patch.multiple(monitor,
                ADGUARD_URL="https://adguard.example",
                ADGUARD_USERNAME="user",
                ADGUARD_PASSWORD="password",
                PUSHOVER_TOKEN="token",
                PUSHOVER_USER="user-key",
                ADGUARD_CA_BUNDLE="",
                VERIFY_TLS=True,
                VERIFY_TLS_SETTING="off"), \
                patch.object(monitor.logger, "warning") as warning, \
                patch.object(monitor, "send_pushover"), \
                patch.object(monitor, "check_adguard", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                monitor.main()
        warning.assert_called_once()
        self.assertIn("remains ENABLED", warning.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
