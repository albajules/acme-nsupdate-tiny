## 2024-05-21 - Command Injection in nsupdate via TSIG Key
**Vulnerability:** The script allowed passing raw `tsig-key` strings directly to `nsupdate` without validation. Newlines in the key string could be used to inject arbitrary `nsupdate` commands.
**Learning:** Even "tiny" scripts must validate external inputs that are passed to subprocesses, especially when those inputs can alter the command structure (like `nsupdate`'s line-based protocol).
**Prevention:** Validate that TSIG keys do not contain newlines or other control characters. Prefer passing keys via files to avoid shell history/process list exposure.
