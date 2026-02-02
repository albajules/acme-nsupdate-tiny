## 2026-02-02 - Protocol Injection in nsupdate
**Vulnerability:** The script used an identifier returned by the ACME server to construct an `nsupdate` command without validation. A malicious server could inject newlines and arbitrary commands.
**Learning:** Even if a protocol implies a certain data format, always validate external inputs before using them in command construction. Trusting the server is insufficient defense against compromised infrastructure or MITM.
**Prevention:** Added regex validation `^[a-zA-Z0-9.*_-]+$` to the identifier received from the ACME server before use.
