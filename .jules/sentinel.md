## 2025-02-18 - [Command Injection via Newline in Key Argument]
**Vulnerability:** The TSIG key argument was passed directly to `nsupdate`'s interactive input stream. A newline character in the key allowed injecting arbitrary commands into `nsupdate`.
**Learning:** Even when using `subprocess.Popen` with a list of arguments (avoiding shell injection), passing data to an interactive subprocess's stdin can still be vulnerable to command injection if the input format uses newlines as delimiters.
**Prevention:** Validate all inputs that are passed to subprocess stdin. Specifically, reject newlines in inputs that are used as single-line arguments or commands within the subprocess's protocol.
