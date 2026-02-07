## 2026-02-07 - [Insecure TSIG Key Handling]
**Vulnerability:** Command injection via TSIG key in `nsupdate` call, and process list exposure of secrets.
**Learning:** `nsupdate` input format is sensitive to newlines. Command line arguments are visible to all users.
**Prevention:** Validate inputs to external commands strictly (no newlines). Support reading secrets from files instead of arguments.
