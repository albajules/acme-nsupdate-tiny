import sys
import os

# Add parent directory to path to import acme_nsupdate_tiny
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acme_nsupdate_tiny
import subprocess

# Mock _cmd to capture the input to nsupdate
def mock_cmd(args, data=None):
    if args[0] == "nsupdate":
        decoded_data = data.decode("utf-8")
        # Check for injection
        if "update add injected.com" in decoded_data:
            # We found the injection! This means the code is VULNERABLE.
            # If we are testing the fix, this should NOT happen.
            # However, since we want to verify the FIX, we expect the code to NOT call this (or fail before).
            # If it calls this with injection, we fail.
            print("FAILURE: Injection succeeded (vulnerability present)")
            sys.exit(1)
        return b""
    return b""

acme_nsupdate_tiny._cmd = mock_cmd

# Test with injected key
key = "name secret\nupdate add injected.com 300 A 1.2.3.4"
cmd = "add _acme-challenge.example.com. 60 txt \"token\""
print(f"Testing with key: {key!r}")

try:
    acme_nsupdate_tiny._nsupdate(cmd, key)
    # If we get here, it means no exception was raised.
    # If the mock detected injection, it would have exited.
    # If the mock didn't detect injection (but it was passed?), that's weird.
    # But for the FIX verification, we EXPECT a ValueError.
    print("FAILURE: No exception raised")
    sys.exit(1)
except ValueError as e:
    print(f"SUCCESS: Caught expected ValueError: {e}")
    if "Invalid TSIG key" not in str(e):
        print("FAILURE: ValueError message incorrect")
        sys.exit(1)
except Exception as e:
    print(f"FAILURE: Caught unexpected Exception: {e}")
    sys.exit(1)

# Also test valid key
valid_key = "hmac-sha256:keyname secret"
print(f"Testing with valid key: {valid_key!r}")
try:
    acme_nsupdate_tiny._nsupdate(cmd, valid_key)
    print("SUCCESS: Valid key accepted")
except Exception as e:
    print(f"FAILURE: Valid key rejected: {e}")
    sys.exit(1)

sys.exit(0)
