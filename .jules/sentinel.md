## 2026-02-13 - [TSIG Key Exposure]
**Vulnerability:** TSIG keys passed via CLI arguments are visible in process listings.
**Learning:** `acme_nsupdate_tiny.py` strictly limited to 100 lines, requiring minimal implementation for reading key files.
**Prevention:** Always prefer file-based secret passing over CLI arguments.
