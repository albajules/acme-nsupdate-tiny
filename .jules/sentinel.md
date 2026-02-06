## 2026-02-06 - Command Injection via Unsanitized TSIG Key
**Vulnerability:** The `nsupdate` input was constructed by concatenating the TSIG key directly with other commands. A key containing newlines could inject arbitrary `nsupdate` commands (e.g., DNS record updates).
**Learning:** Even when using `subprocess` with `shell=False`, if the input to the subprocess is a script or formatted text (like `nsupdate`'s stdin), internal injection is still possible if delimiters (like newlines) are not sanitized.
**Prevention:** Always validate and sanitize inputs that are used to construct scripts or protocols, even for internal tools. Enforce strict character sets (e.g., no newlines) for keys and secrets.
