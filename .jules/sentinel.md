## 2024-10-24 - Injection via Subprocess Input Stream
**Vulnerability:** Command injection in `nsupdate` via the TSIG key argument.
**Learning:** Even when using `subprocess.Popen` with `shell=False`, data passed to the stdin of the subprocess can be a vector for command injection if the subprocess accepts text-based commands (like `nsupdate` or `sql` shells).
**Prevention:** Validate all inputs that are concatenated into command streams, especially newlines which often serve as command separators.
