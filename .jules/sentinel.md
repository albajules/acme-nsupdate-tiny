## 2026-02-15 - Secure Secret Handling in Minimalist Scripts
**Vulnerability:** TSIG keys passed via CLI arguments are exposed in process listings.
**Learning:** In ultra-minimal scripts (<100 lines), security features like secure file reading can be implemented concisely using conditional file checks.
**Prevention:** Always support file paths for sensitive arguments, prioritizing file reading over string handling when possible.
