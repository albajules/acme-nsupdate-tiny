import unittest
import sys
import os
from unittest.mock import patch

# Add parent directory to path to import script
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acme_nsupdate_tiny

class TestAcmeNsupdateTiny(unittest.TestCase):
    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_file(self, mock_sign):
        # Create a temporary key file
        key_content = 'hmac-sha256:key secret'
        key_file = 'temp_tsig.key'
        with open(key_file, 'w') as f:
            f.write(key_content)

        try:
            acme_nsupdate_tiny.main(['--account-key', 'account.key', '--csr', 'domain.csr', '--tsig-key', key_file])

            expected_staging_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
            mock_sign.assert_called_with('account.key', 'domain.csr', expected_staging_url, key_content, None)
        finally:
            if os.path.exists(key_file):
                os.remove(key_file)

    @patch('acme_nsupdate_tiny.sign')
    def test_tsig_key_string(self, mock_sign):
        key_content = 'hmac-sha256:key secret'
        acme_nsupdate_tiny.main(['--account-key', 'account.key', '--csr', 'domain.csr', '--tsig-key', key_content])

        expected_staging_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
        mock_sign.assert_called_with('account.key', 'domain.csr', expected_staging_url, key_content, None)

    def test_tsig_key_newline_error(self):
        # Test with newline in string argument
        with self.assertRaises(ValueError) as cm:
             acme_nsupdate_tiny.main(['--account-key', 'account.key', '--csr', 'domain.csr', '--tsig-key', 'hmac-sha256:key\nsecret'])
        self.assertIn("TSIG key must not contain newlines", str(cm.exception))

    def test_tsig_key_file_newline_error(self):
        # Test with newline in file content
        key_content = 'hmac-sha256:key\nsecret'
        key_file = 'temp_tsig_bad.key'
        with open(key_file, 'w') as f:
            f.write(key_content)

        try:
            with self.assertRaises(ValueError) as cm:
                acme_nsupdate_tiny.main(['--account-key', 'account.key', '--csr', 'domain.csr', '--tsig-key', key_file])
            self.assertIn("TSIG key must not contain newlines", str(cm.exception))
        finally:
            if os.path.exists(key_file):
                os.remove(key_file)

if __name__ == '__main__':
    unittest.main()
