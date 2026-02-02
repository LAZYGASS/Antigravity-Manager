## 2026-02-01 - Unredacted Sensitive Data in Local Logs
**Vulnerability:** The `ProxyRequestLog` system (backed by SQLite) captured full request and response bodies, including potential API keys and secrets, without any redaction layer.
**Learning:** Middleware logging in proxy applications often captures "everything" for debugging, but this inadvertently creates a persistent store of credentials on disk.
**Prevention:** Implement a `redact_sensitive_data` utility that sanitizes JSON payloads before any logging or storage occurs. Ensure this utility is applied to all data ingress/egress points in the logging pipeline.
