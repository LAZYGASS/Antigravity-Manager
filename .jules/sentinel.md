## 2025-05-14 - Arbitrary File Read in Image Processing
**Vulnerability:** The `transform_openai_request` function allowed reading arbitrary local files via `file://` URLs or absolute paths in the `image_url` field, leading to potential Local File Inclusion (LFI).
**Learning:** Convenience features (like "just pass a file path") in backend proxies can become critical vulnerabilities when they bypass client-side validation and allow the server to access its own filesystem based on untrusted input.
**Prevention:** Disable server-side local file reading for API proxies. Require clients to send file content (e.g., Base64) instead of paths.
