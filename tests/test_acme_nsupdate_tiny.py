
import sys
import os
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import acme_nsupdate_tiny

class TestAcmeNsupdateTiny(unittest.TestCase):
    def setUp(self):
        # Mock _cmd to prevent actual execution
        self.original_cmd = acme_nsupdate_tiny._cmd
        self.cmd_calls = []
        def mock_cmd(args, data=None):
            self.cmd_calls.append((args, data))
            return b""
        acme_nsupdate_tiny._cmd = mock_cmd

        # Mock sign to prevent actual logic execution when main is called
        # We only want to test argument parsing and key loading in main
        self.original_sign = acme_nsupdate_tiny.sign
        self.sign_calls = []
        def mock_sign(keyfile, csrfile, directory_url, nskey=None, emails=None):
            self.sign_calls.append((keyfile, csrfile, directory_url, nskey, emails))
            return "certificate"
        acme_nsupdate_tiny.sign = mock_sign

    def tearDown(self):
        acme_nsupdate_tiny._cmd = self.original_cmd
        acme_nsupdate_tiny.sign = self.original_sign

    def test_nsupdate_injection(self):
        # Should raise ValueError if key contains newline
        with self.assertRaises(ValueError):
            acme_nsupdate_tiny._nsupdate("cmd", "key\nnewline")

    def test_main_file_loading(self):
        # Create a temporary key file
        key_content = "hmac-sha256:key secret"
        key_file = "test.key"
        with open(key_file, "w") as f:
            f.write(key_content)

        try:
            # Call main with the key file path
            # We need to pass required args too
            args = ["--account-key", "account.key", "--csr", "domain.csr", "--tsig-key", key_file]
            acme_nsupdate_tiny.main(args)

            # Verify sign was called with the content of the key file
            self.assertEqual(len(self.sign_calls), 1)
            # The 4th argument to sign is nskey
            self.assertEqual(self.sign_calls[0][3], key_content)
        finally:
            if os.path.exists(key_file):
                os.remove(key_file)

    def test_main_direct_key(self):
        # Test backward compatibility: passing key string directly
        key_content = "hmac-sha256:key secret"
        # Ensure it doesn't exist as file
        if os.path.exists(key_content):
            os.remove(key_content)

        args = ["--account-key", "account.key", "--csr", "domain.csr", "--tsig-key", key_content]
        acme_nsupdate_tiny.main(args)

        # Verify sign was called with the key string
        self.assertEqual(len(self.sign_calls), 1)
        self.assertEqual(self.sign_calls[0][3], key_content)

if __name__ == "__main__":
    unittest.main()
