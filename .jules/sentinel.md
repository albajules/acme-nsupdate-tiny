## 2026-02-14 - TSIG Key Exposure and Injection
**Vulnerability:** TSIG keys were accepted only as command-line arguments, exposing them in process lists. Additionally, keys were not validated for newlines, which could allow command injection into the `nsupdate` utility.
**Learning:** Command-line arguments are inherently insecure for secrets. Utilities like `nsupdate` that accept commands via stdin are vulnerable to injection if inputs containing newlines are passed directly.
**Prevention:** Always allow secrets to be read from files or environment variables. Strictly validate inputs to external commands, especially for control characters like newlines.
