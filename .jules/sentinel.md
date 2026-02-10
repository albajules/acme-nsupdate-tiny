## 2026-02-10 - [Process Argument Exposure]
**Vulnerability:** TSIG key passed as command line argument, visible via `ps aux`.
**Learning:** Secrets should never be passed as command line arguments because they are world-readable in process lists.
**Prevention:** Accept secrets via file paths or environment variables.
