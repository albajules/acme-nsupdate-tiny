import unittest
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

# Ensure we can import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import acme_nsupdate_tiny

class TestAcmeNsupdateTiny(unittest.TestCase):
    def test_tsig_key_validation(self):
        """Test that newlines in TSIG key raise ValueError"""
        with self.assertRaises(ValueError) as cm:
            acme_nsupdate_tiny._nsupdate("cmd", "key\nname")
        self.assertIn("TSIG key must not contain newlines", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            acme_nsupdate_tiny._nsupdate("cmd", "key\rname")
        self.assertIn("TSIG key must not contain newlines", str(cm.exception))

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_file_loading(self, mock_sign):
        """Test that TSIG key is read from file if it exists"""
        # Create a temp file with the key
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("hmac-sha256:testkey secret")
            key_path = f.name

        try:
            # Prepare arguments
            argv = [
                '--account-key', 'account.key',
                '--csr', 'domain.csr',
                '--tsig-key', key_path
            ]

            # Call main
            acme_nsupdate_tiny.main(argv)

            # Verify sign was called with the content of the file
            mock_sign.assert_called_once()
            args, _ = mock_sign.call_args
            # args: keyfile, csrfile, directory_url, nskey, emails
            self.assertEqual(args[3], "hmac-sha256:testkey secret")

        finally:
            os.remove(key_path)

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_string(self, mock_sign):
        """Test that TSIG key is used as-is if not a file"""
        key_str = "hmac-sha256:stringkey secret"
        argv = [
            '--account-key', 'account.key',
            '--csr', 'domain.csr',
            '--tsig-key', key_str
        ]

        acme_nsupdate_tiny.main(argv)

        mock_sign.assert_called_once()
        args, _ = mock_sign.call_args
        self.assertEqual(args[3], key_str)

if __name__ == '__main__':
    unittest.main()
