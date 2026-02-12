import unittest
import sys
import os
import argparse
from unittest.mock import patch

# Adjust path to import the module from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    import acme_nsupdate_tiny
except ImportError:
    # If running from root, just import directly if sys.path setup failed (unlikely)
    import acme_nsupdate_tiny

class TestAcmeNsupdateTiny(unittest.TestCase):

    def setUp(self):
        # Create dummy files required by argparse
        # Using specific names to avoid conflicts, but simple names for readability
        self.account_key_file = "test_account.key"
        self.csr_file = "test_domain.csr"
        with open(self.account_key_file, "w") as f: f.write("dummy key")
        with open(self.csr_file, "w") as f: f.write("dummy csr")

    def tearDown(self):
        if os.path.exists(self.account_key_file): os.remove(self.account_key_file)
        if os.path.exists(self.csr_file): os.remove(self.csr_file)
        if os.path.exists("test_tsig.key"): os.remove("test_tsig.key")

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_from_file(self, mock_sign):
        # Create a TSIG key file
        key_content = "hmac-sha256:testkey secret"
        key_filename = "test_tsig.key"
        with open(key_filename, "w") as f:
            f.write(key_content)

        # Call main with the filename
        argv = [
            "--account-key", self.account_key_file,
            "--csr", self.csr_file,
            "--tsig-key", key_filename
        ]

        # Suppress stdout/stderr and logging
        with patch('sys.stdout'), patch('sys.stderr'), patch('logging.basicConfig'):
            acme_nsupdate_tiny.main(argv)

        # Check if sign was called with the CONTENT of the key file
        # args passed to sign: (keyfile, csrfile, directory_url, nskey, emails)
        # We expect nskey to be key_content
        args, _ = mock_sign.call_args
        self.assertEqual(args[3], key_content)

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_direct_string(self, mock_sign):
        key_content = "hmac-sha256:directkey secret"

        argv = [
            "--account-key", self.account_key_file,
            "--csr", self.csr_file,
            "--tsig-key", key_content
        ]

        with patch('sys.stdout'), patch('sys.stderr'), patch('logging.basicConfig'):
            acme_nsupdate_tiny.main(argv)

        args, _ = mock_sign.call_args
        self.assertEqual(args[3], key_content)

    def test_newline_validation(self):
        # Test validation in _nsupdate
        with self.assertRaises(ValueError) as cm:
            acme_nsupdate_tiny._nsupdate("cmd", "key\nnewline")
        self.assertIn("must not contain newlines", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            acme_nsupdate_tiny._nsupdate("cmd", "key\rreturn")
        self.assertIn("must not contain newlines", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
