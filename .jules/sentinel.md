## 2026-01-24 - [Logging of Sensitive Data in Local DB]
**Vulnerability:** Full request/response bodies were being logged to the local SQLite database in plain text, potentially exposing API keys and PII.
**Learning:** Even in local-first desktop apps, logging middleware must treat all data as potentially sensitive and redact secrets before storage.
**Prevention:** Implement proactive redaction in logging middleware using robust parsing (JSON) with regex fallbacks for known secret keys.
