## 2024-05-22 - [TSIG Key Exposure & Injection]
**Vulnerability:** TSIG key passed as command-line argument was visible in process list and vulnerable to newline injection.
**Learning:** Scripts wrapping external commands must validate inputs strictly (no newlines) and prefer file-based secret passing.
**Prevention:** Use file paths for secrets; validate input against strictly expected patterns.
