# v1.4.1 — Diagnostic: show why endpoints fail + DNS-independent test

- Every failed endpoint now prints its real failure reason (e.g. DNS error, connection timeout, HTTP status) instead of just "Failed", so a 0-result scan can actually be diagnosed.
- The tunnel test no longer depends on Xray's DNS (8.8.8.8), which some networks block or intercept: the scanner resolves www.gstatic.com once with the system resolver and tests the tunnel against the resolved IP (with the original Host header), so Xray never has to resolve the test target. If resolution fails it falls back to the hostname as before.
- Build fix: the packaging directory is cleaned before each build so a stale `result.csv` from a local test run can never end up in the release archive.
