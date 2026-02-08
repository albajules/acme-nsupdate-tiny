import sys
import os
import unittest
# Add parent directory to path to import acme_nsupdate_tiny
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import acme_nsupdate_tiny
from unittest.mock import patch, MagicMock

STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

class TestAcmeNsupdateTiny(unittest.TestCase):
    def setUp(self):
        self.account_key = "account.key"
        self.csr = "domain.csr"
        self.tsig_key_str = "hmac-sha256:keyname secret"
        self.tsig_key_file = "tsig.key"
        with open(self.tsig_key_file, "w") as f:
            f.write(self.tsig_key_str)

    def tearDown(self):
        if os.path.exists(self.tsig_key_file):
            os.remove(self.tsig_key_file)

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_string(self, mock_sign):
        # Test passing key as string
        argv = ["--account-key", self.account_key, "--csr", self.csr, "--tsig-key", self.tsig_key_str]
        acme_nsupdate_tiny.main(argv)
        mock_sign.assert_called_with(self.account_key, self.csr, STAGING_URL, self.tsig_key_str, None)

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_file(self, mock_sign):
        # Test passing key as file
        argv = ["--account-key", self.account_key, "--csr", self.csr, "--tsig-key", self.tsig_key_file]
        acme_nsupdate_tiny.main(argv)
        # Should be called with the content of the file
        mock_sign.assert_called_with(self.account_key, self.csr, STAGING_URL, self.tsig_key_str, None)

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_newline_validation(self, mock_sign):
        # Test validating newlines
        key_with_newline = "hmac-sha256:keyname\nsecret"
        argv = ["--account-key", self.account_key, "--csr", self.csr, "--tsig-key", key_with_newline]

        # We expect ValueError. If not raised, mock_sign will be called (which is fine, but assertRaises will fail)
        with self.assertRaises(ValueError):
             acme_nsupdate_tiny.main(argv)

if __name__ == '__main__':
    unittest.main()
