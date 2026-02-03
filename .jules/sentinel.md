## 2024-05-22 - NSUpdate Command Injection
**Vulnerability:** The `nsupdate` command allows command injection via the TSIG key argument because it is passed directly to stdin without validation.
**Learning:** Even when using `subprocess` with `shell=False`, if the subprocess reads commands from stdin (like `nsupdate`), injection is possible if input is not sanitized.
**Prevention:** Validate all inputs that are passed to subprocess stdin, especially if they are used as part of a command protocol.
