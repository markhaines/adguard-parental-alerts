import tempfile
import unittest
from unittest.mock import Mock, patch

import monitor


class TlsTests(unittest.TestCase):
    def state(self):
        return {"version": 2, "cursor": None, "pending": [], "initialised": False}

    def session(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200)
        session.get.return_value.raise_for_status.return_value = None
        session.get.return_value.json.return_value = {"data": []}
        return session

    def test_tls_verification_is_enabled_by_default(self):
        session = self.session()
        with patch.multiple(monitor, VERIFY_TLS=True, ADGUARD_CA_BUNDLE=""), \
                patch.object(monitor.requests, "Session", return_value=session), \
                patch.object(monitor, "save_state"):
            monitor.check_adguard(self.state())
        self.assertIs(session.verify, True)

    def test_custom_ca_bundle_is_used(self):
        session = self.session()
        with patch.multiple(monitor, VERIFY_TLS=True, ADGUARD_CA_BUNDLE="/ca/private.pem"), \
                patch.object(monitor.requests, "Session", return_value=session), \
                patch.object(monitor, "save_state"):
            monitor.check_adguard(self.state())
        self.assertEqual(session.verify, "/ca/private.pem")

    def test_tls_verification_can_be_explicitly_disabled(self):
        session = self.session()
        with patch.multiple(monitor, VERIFY_TLS=False, ADGUARD_CA_BUNDLE="/unused.pem"), \
                patch.object(monitor.requests, "Session", return_value=session), \
                patch.object(monitor, "save_state"):
            monitor.check_adguard(self.state())
        self.assertIs(session.verify, False)

    def test_tls_setting_parsing(self):
        for value in ("0", "false", "no", " FALSE "):
            self.assertFalse(monitor.tls_verification_enabled(value))
        for value in ("", "garbage", "1", "yes"):
            self.assertTrue(monitor.tls_verification_enabled(value))

    def test_noncanonical_tls_values_are_unknown(self):
        for value in ("off", "falsse", "garbage", ""):
            self.assertFalse(monitor.tls_verification_setting_known(value))


class StartupTlsTests(unittest.TestCase):
    def config(self, **extra):
        values = dict(ADGUARD_URL="https://adguard.example", ADGUARD_USERNAME="user",
                      ADGUARD_PASSWORD="password", PUSHOVER_TOKEN="token",
                      PUSHOVER_USER="key", VERIFY_TLS=True,
                      VERIFY_TLS_SETTING="true", ADGUARD_CA_BUNDLE="")
        values.update(extra)
        return patch.multiple(monitor, **values)

    def assert_invalid_ca(self, contents):
        with tempfile.NamedTemporaryFile(mode="w") as bundle:
            bundle.write(contents)
            bundle.flush()
            with self.config(ADGUARD_CA_BUNDLE=bundle.name), \
                    patch.object(monitor, "send_pushover"), \
                    patch.object(monitor.logger, "error") as error:
                with self.assertRaises(SystemExit) as raised:
                    monitor.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("not a valid PEM", error.call_args.args[0])

    def test_missing_ca_bundle_exits(self):
        with self.config(ADGUARD_CA_BUNDLE="/missing/ca.pem"), \
                patch.object(monitor, "send_pushover"), patch.object(monitor.logger, "error"):
            with self.assertRaises(SystemExit) as raised:
                monitor.main()
        self.assertEqual(raised.exception.code, 1)

    def test_empty_ca_bundle_exits(self):
        self.assert_invalid_ca("")

    def test_garbage_ca_bundle_exits(self):
        self.assert_invalid_ca("not a PEM certificate")

    def test_http_url_does_not_validate_ca_bundle(self):
        with self.config(ADGUARD_URL="http://192.168.10.21:80", ADGUARD_CA_BUNDLE="/missing/ca.pem"), \
                patch.object(monitor, "send_pushover"), patch.object(monitor, "load_state"), \
                patch.object(monitor, "check_adguard", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                monitor.main()

    def test_disabled_verification_warns(self):
        with self.config(VERIFY_TLS=False, ADGUARD_CA_BUNDLE="/unused.pem"), \
                patch.object(monitor.logger, "warning") as warning, \
                patch.object(monitor, "send_pushover"), patch.object(monitor, "load_state"), \
                patch.object(monitor, "check_adguard", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                monitor.main()
        self.assertIn("DISABLED", warning.call_args.args[0])

    def test_unrecognized_setting_warns_and_fails_closed(self):
        with self.config(VERIFY_TLS=True, VERIFY_TLS_SETTING="off"), \
                patch.object(monitor.logger, "warning") as warning, \
                patch.object(monitor, "send_pushover"), patch.object(monitor, "load_state"), \
                patch.object(monitor, "check_adguard", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                monitor.main()
        self.assertIn("remains ENABLED", warning.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
