## 2026-01-23 - Timing Attack in Auth Middleware
**Vulnerability:** API Key comparison in `auth_middleware` used standard string equality (`==`), allowing potential timing attacks to guess the key.
**Learning:** Even local-first applications listening on network ports (optional `0.0.0.0`) must treat auth checks with standard cryptographic rigor. "Constant-time compare is unnecessary here" comments are often proven wrong when threat models expand (e.g., LAN access).
**Prevention:** Always use constant-time comparison helpers for secret validation. Avoid `==` for secrets.
