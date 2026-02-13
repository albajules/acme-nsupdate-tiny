import unittest
import sys
import os
import tempfile
from unittest.mock import patch, MagicMock

# Add parent directory to path to import acme_nsupdate_tiny
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import acme_nsupdate_tiny

class TestAcmeNsupdateTiny(unittest.TestCase):
    def setUp(self):
        # Prevent logging output during tests
        pass

    @patch('acme_nsupdate_tiny.sign')
    def test_key_string(self, mock_sign):
        # Test passing key as string directly
        key_str = "hmac-sha256:keyname secret"
        argv = [
            "--account-key", "account.key",
            "--csr", "domain.csr",
            "--tsig-key", key_str
        ]

        acme_nsupdate_tiny.main(argv)

        mock_sign.assert_called_once()
        args, _ = mock_sign.call_args
        # sign(keyfile, csrfile, directory_url, nskey=None, emails=None)
        self.assertEqual(args[3], key_str)

    @patch('acme_nsupdate_tiny.sign')
    def test_key_file(self, mock_sign):
        # Test passing key via file
        key_content = "hmac-sha256:keyname secret_from_file"
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(key_content)
            tmp_path = tmp.name

        try:
            argv = [
                "--account-key", "account.key",
                "--csr", "domain.csr",
                "--tsig-key", tmp_path
            ]

            acme_nsupdate_tiny.main(argv)

            mock_sign.assert_called_once()
            args, _ = mock_sign.call_args
            self.assertEqual(args[3], key_content)
        finally:
            os.remove(tmp_path)

    @patch('acme_nsupdate_tiny.sign')
    def test_key_file_with_newline(self, mock_sign):
        # Test passing key via file with newline
        key_content = "hmac-sha256:keyname secret_from_file"
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(key_content + "\n")
            tmp_path = tmp.name

        try:
            argv = [
                "--account-key", "account.key",
                "--csr", "domain.csr",
                "--tsig-key", tmp_path
            ]

            acme_nsupdate_tiny.main(argv)

            mock_sign.assert_called_once()
            args, _ = mock_sign.call_args
            self.assertEqual(args[3], key_content) # Should be stripped
        finally:
            os.remove(tmp_path)

    @patch('acme_nsupdate_tiny.sign')
    def test_non_existent_file(self, mock_sign):
        # Test passing non-existent file path (should be treated as key string)
        fake_path = "/path/to/non/existent/file"
        argv = [
            "--account-key", "account.key",
            "--csr", "domain.csr",
            "--tsig-key", fake_path
        ]

        acme_nsupdate_tiny.main(argv)

        mock_sign.assert_called_once()
        args, _ = mock_sign.call_args
        self.assertEqual(args[3], fake_path)

if __name__ == '__main__':
    unittest.main()
