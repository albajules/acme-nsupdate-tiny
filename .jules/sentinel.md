## 2024-05-23 - Injection via subprocess stdin helper arguments
**Vulnerability:** Command injection in `nsupdate` wrapper via newline injection in `tsig-key` argument.
**Learning:** Helper functions constructing stdin for subprocesses via string concatenation are vulnerable if arguments are not sanitized against protocol delimiters (newlines).
**Prevention:** Validate inputs to command wrappers to ensure they don't contain control characters or protocol delimiters.
