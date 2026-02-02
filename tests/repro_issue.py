import sys
import os
import unittest
import json
try:
    from unittest.mock import MagicMock, patch
except ImportError:
    # Python 2
    from mock import MagicMock, patch

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acme_nsupdate_tiny

# Dummy data
KEY_TEXT = """
Private-Key: (2048 bit)
modulus:
    00:aa:bb:cc
publicExponent: 65537 (0x10001)
"""

CSR_TEXT = """
Subject: CN=example.com
X509v3 Subject Alternative Name:
    DNS:example.com
"""

class TestSecurity(unittest.TestCase):
    def test_malicious_identifier_injection(self):
        # Store nsupdate calls
        nsupdate_calls = []

        def mock_cmd(args, data=None):
            cmd = args[0]
            if cmd == "openssl":
                if args[1] == "rsa":
                    return KEY_TEXT.encode('utf-8')
                if args[1] == "req":
                    if "-outform" in args:
                        return b"DER_CSR"
                    return CSR_TEXT.encode('utf-8')
                if args[1] == "dgst":
                    return b"signature"
            if cmd == "nsupdate":
                nsupdate_calls.append(data.decode('utf-8'))
                return b""
            return b""

        # Mock responses
        responses = {
            "directory": {
                "newNonce": "http://acme/nonce",
                "newAccount": "http://acme/account",
                "newOrder": "http://acme/order",
            },
            "nonce": "",
            "account": {"status": "valid"},
            "order": {
                "authorizations": ["http://acme/authz/1"],
                "finalize": "http://acme/finalize",
                "certificate": "http://acme/cert",
                "status": "pending"
            },
            "authz": {
                "identifier": {"type": "dns", "value": "example.com\nmalicious"},
                "challenges": [{"type": "dns-01", "url": "http://acme/chall/1", "token": "token"}],
                "status": "pending"
            },
            "chall": {"status": "valid"},
            "finalize": {"status": "valid", "certificate": "http://acme/cert"},
            "order_valid": {"status": "valid", "certificate": "http://acme/cert"}
        }

        def mock_urlopen(req):
            url = req.get_full_url()
            resp = MagicMock()
            resp.getcode.return_value = 200
            resp.info.return_value = {"Replay-Nonce": "nonce123", "Location": "http://acme/loc"}

            data = "{}"
            if url == "http://acme/directory":
                data = json.dumps(responses["directory"])
            elif url == "http://acme/nonce":
                resp.getcode.return_value = 204
                data = ""
            elif url == "http://acme/account":
                data = json.dumps(responses["account"])
            elif url == "http://acme/order":
                data = json.dumps(responses["order"])
            elif url == "http://acme/authz/1":
                data = json.dumps(responses["authz"])
            elif url == "http://acme/chall/1":
                data = json.dumps(responses["chall"])
            elif url == "http://acme/finalize":
                 data = json.dumps(responses["order_valid"])
            elif url == "http://acme/loc":
                 data = json.dumps(responses["order_valid"])

            resp.read.return_value = data.encode('utf-8')
            return resp

        # Patch
        with patch('acme_nsupdate_tiny._cmd', side_effect=mock_cmd):
            with patch('acme_nsupdate_tiny.urlopen', side_effect=mock_urlopen):
                 # Run sign
                 try:
                     acme_nsupdate_tiny.sign("account.key", "domain.csr", "http://acme/directory")
                 except Exception as e:
                     # It might fail because of validation or other things, but we want to check side effects
                     print("Exception during sign: " + str(e))

        # Check calls
        found_malicious = False
        for call in nsupdate_calls:
            print("NSUPDATE CALL: " + call)
            if "example.com\nmalicious" in call:
                found_malicious = True

        if found_malicious:
             self.fail("VULNERABILITY REPRODUCED: Malicious identifier passed to nsupdate")
        else:
             print("VULNERABILITY NOT REPRODUCED (Safe)")

if __name__ == '__main__':
    unittest.main()
