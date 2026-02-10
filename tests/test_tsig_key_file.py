import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acme_nsupdate_tiny

class TestTSIGKeyFile(unittest.TestCase):
    def test_main_exists(self):
        """Verify that main function exists (will fail initially)"""
        self.assertTrue(hasattr(acme_nsupdate_tiny, 'main'), "main function not found in acme_nsupdate_tiny")

    @patch('acme_nsupdate_tiny.sign')
    def test_key_file_loading(self, mock_sign):
        # Create a temporary key file
        key_content = "hmac-sha256:keyname secret"
        key_file_path = "temp_tsig.key"
        with open(key_file_path, "w") as f:
            f.write(key_content + "\n") # Add newline

        try:
            argv = [
                "--account-key", "account.key",
                "--csr", "domain.csr",
                "--tsig-key", key_file_path
            ]

            # Mock print to suppress output
            with patch('builtins.print'):
                if hasattr(acme_nsupdate_tiny, 'main'):
                    acme_nsupdate_tiny.main(argv)
                else:
                    self.fail("main function not implemented yet")

            # Verify sign was called with the key content (stripped)
            args, _ = mock_sign.call_args
            # sign(keyfile, csrfile, directory_url, nskey=None, emails=None)
            # nskey is the 4th argument (index 3)
            self.assertEqual(args[3], key_content)

        finally:
            if os.path.exists(key_file_path):
                os.remove(key_file_path)

    @patch('acme_nsupdate_tiny.sign')
    def test_key_string_loading(self, mock_sign):
        key_content = "hmac-sha256:keyname secret"
        argv = [
            "--account-key", "account.key",
            "--csr", "domain.csr",
            "--tsig-key", key_content
        ]

        with patch('builtins.print'):
            if hasattr(acme_nsupdate_tiny, 'main'):
                acme_nsupdate_tiny.main(argv)
            else:
                self.fail("main function not implemented yet")

        args, _ = mock_sign.call_args
        self.assertEqual(args[3], key_content)

    def test_key_with_newlines_raises_error(self):
        key_content = "hmac-sha256:keyname\nsecret"
        argv = [
            "--account-key", "account.key",
            "--csr", "domain.csr",
            "--tsig-key", key_content
        ]

        with patch('acme_nsupdate_tiny.sign'):
             if hasattr(acme_nsupdate_tiny, 'main'):
                 with self.assertRaises(ValueError):
                    acme_nsupdate_tiny.main(argv)
             else:
                 self.fail("main function not implemented yet")

if __name__ == '__main__':
    unittest.main()
