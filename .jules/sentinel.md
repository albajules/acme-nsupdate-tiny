## 2024-10-25 - CLI Secret Exposure
**Vulnerability:** Passing secrets (TSIG key) as command line arguments exposes them to all users via process listing (`ps aux`).
**Learning:** Python scripts using `argparse` for secrets need alternative input methods (file/env) to avoid exposure in process tables.
**Prevention:** Always support reading secrets from files or environment variables, and validate that secret files are readable and have appropriate permissions.
