import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import acme_nsupdate_tiny

class TestInjection(unittest.TestCase):
    @patch('subprocess.Popen')
    def test_nsupdate_injection(self, mock_popen):
        process_mock = MagicMock()
        process_mock.communicate.return_value = (b"", b"")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        malicious_key = "keyname secret\ninjection"

        # We expect ValueError now
        with self.assertRaisesRegex(ValueError, "TSIG key must not contain newlines"):
            acme_nsupdate_tiny._nsupdate("add example.com 300 A 1.2.3.4", malicious_key)

        print("\n[SUCCESS] ValueError raised for malicious key.")

if __name__ == '__main__':
    unittest.main()
