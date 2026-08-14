import unittest
from unittest.mock import Mock, patch

import monitor


class TlsTests(unittest.TestCase):
    def test_tls_verification_is_enabled_by_default(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200)
        session.get.return_value.json.return_value = {"data": []}
        with patch.object(monitor.requests, "Session", return_value=session):
            monitor.check_adguard()
        self.assertIs(session.verify, True)

    def test_custom_ca_bundle_is_used(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200)
        session.get.return_value.json.return_value = {"data": []}
        with patch.object(monitor, "ADGUARD_CA_BUNDLE", "/ca/private.pem"), \
                patch.object(monitor.requests, "Session", return_value=session):
            monitor.check_adguard()
        self.assertEqual(session.verify, "/ca/private.pem")


if __name__ == "__main__":
    unittest.main()
