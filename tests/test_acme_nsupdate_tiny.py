import unittest
import sys
import os
from unittest.mock import patch, mock_open

# Add parent directory to path to import acme_nsupdate_tiny
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import acme_nsupdate_tiny

class TestAcmeNsupdateTiny(unittest.TestCase):

    @patch('acme_nsupdate_tiny._cmd')
    def test_nsupdate_command_injection_prevention(self, mock_cmd):
        # Verify that passing a key with newline raises ValueError in _nsupdate
        key_with_injection = "hmac-sha256:keyname secret\nupdate add malicious.com 300 A 1.2.3.4"
        cmd = "add _acme-challenge.example.com. 1 txt \"record\""

        with self.assertRaisesRegex(ValueError, "TSIG key must not contain newlines"):
            acme_nsupdate_tiny._nsupdate(cmd, key_with_injection)

    @patch('acme_nsupdate_tiny.sign')
    @patch('os.path.isfile')
    @patch('builtins.open', new_callable=mock_open, read_data="hmac-sha256:keyname secret_from_file")
    def test_main_loads_key_from_file(self, mock_file, mock_isfile, mock_sign):
        # Setup mocks
        mock_isfile.return_value = True
        mock_sign.return_value = "certificate_content"

        # Call main with a file path for tsig-key
        argv = ["--account-key", "account.key", "--csr", "domain.csr", "--tsig-key", "/path/to/keyfile"]
        acme_nsupdate_tiny.main(argv)

        # Verify file was opened
        mock_file.assert_called_with("/path/to/keyfile")

        # Verify sign was called with the content of the file
        mock_sign.assert_called_once()
        args, _ = mock_sign.call_args
        # args: (account_key, csr, directory, tsig_key, email)
        self.assertEqual(args[3], "hmac-sha256:keyname secret_from_file")

    @patch('acme_nsupdate_tiny.sign')
    @patch('os.path.isfile')
    def test_main_uses_key_string_if_not_file(self, mock_isfile, mock_sign):
        # Setup mocks
        mock_isfile.return_value = False
        mock_sign.return_value = "certificate_content"

        # Call main with a key string
        key_string = "hmac-sha256:keyname secret_string"
        argv = ["--account-key", "account.key", "--csr", "domain.csr", "--tsig-key", key_string]
        acme_nsupdate_tiny.main(argv)

        # Verify sign was called with the key string
        mock_sign.assert_called_once()
        args, _ = mock_sign.call_args
        self.assertEqual(args[3], key_string)

if __name__ == '__main__':
    unittest.main()
