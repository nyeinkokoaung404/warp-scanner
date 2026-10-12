# v1.2.0 — WARP IP scanner only

- Removed WARP account registration and WireGuard config generation entirely. The scanner no longer contacts `api.cloudflareclient.com`, so it works even on networks where WARP registration is blocked.
- Removed the "situation" and custom-noise setup steps. The flow is now: scan mode → IP version → results.
- Direct TCP reachability probes of WARP IP endpoints, sorted by average latency, exported to `result.csv`.
- No Xray-core dependency; standalone binaries.
