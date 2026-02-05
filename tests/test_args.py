import unittest
import sys
import os
import tempfile

# Add parent directory to path to import acme_nsupdate_tiny
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_nsupdate_tiny import parse_args

class TestArgs(unittest.TestCase):
    def test_key_from_string(self):
        """Test that passing a key as a string works (backward compatibility)."""
        key = "hmac-sha256:keyname secret"
        argv = ["--account-key", "a.key", "--csr", "d.csr", "--tsig-key", key]
        args = parse_args(argv)
        self.assertEqual(args.tsig_key, key)

    def test_key_from_file(self):
        """Test that passing a key as a file path works."""
        key_content = "hmac-sha256:filekey secret"
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
            tf.write(key_content)
            tf_path = tf.name

        try:
            argv = ["--account-key", "a.key", "--csr", "d.csr", "--tsig-key", tf_path]
            args = parse_args(argv)
            self.assertEqual(args.tsig_key, key_content)
        finally:
            os.remove(tf_path)

    def test_key_from_file_with_newline(self):
        """Test that trailing newlines are stripped when reading from file."""
        key_content = "hmac-sha256:filekey secret"
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
            tf.write(key_content + "\n")
            tf_path = tf.name

        try:
            argv = ["--account-key", "a.key", "--csr", "d.csr", "--tsig-key", tf_path]
            args = parse_args(argv)
            self.assertEqual(args.tsig_key, key_content)
        finally:
            os.remove(tf_path)

    def test_key_with_internal_newline_raises(self):
        """Test that keys with internal newlines raise ValueError."""
        key = "hmac-sha256:key\nname secret"
        argv = ["--account-key", "a.key", "--csr", "d.csr", "--tsig-key", key]
        with self.assertRaises(ValueError) as cm:
            parse_args(argv)
        self.assertIn("must not contain newlines", str(cm.exception))

    def test_key_from_file_with_internal_newline_raises(self):
        """Test that keys with internal newlines from file raise ValueError."""
        key_content = "hmac-sha256:key\nname secret"
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
            tf.write(key_content)
            tf_path = tf.name

        try:
            argv = ["--account-key", "a.key", "--csr", "d.csr", "--tsig-key", tf_path]
            with self.assertRaises(ValueError) as cm:
                parse_args(argv)
            self.assertIn("must not contain newlines", str(cm.exception))
        finally:
            os.remove(tf_path)

if __name__ == '__main__':
    unittest.main()
