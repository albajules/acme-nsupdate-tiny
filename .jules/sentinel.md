## 2026-02-11 - TSIG Key Injection and Exposure
**Vulnerability:** TSIG key passed as command line argument is visible in process list. Also, unvalidated input to  allows command injection via newlines.
**Learning:** Even if a script is "tiny", input validation is critical. Passing secrets via command-line arguments is inherently insecure due to process listing.
**Prevention:** Support file-based secret loading. Validate all inputs before passing to subprocesses, especially those interpreting line-based protocols.
