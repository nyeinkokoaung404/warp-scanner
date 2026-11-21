# v1.4.0 — Upstream rewrite, no account registration

- Rewritten following upstream BPB-Warp-Scanner: endpoints are now tested end-to-end through a real WireGuard tunnel (Xray-core) instead of TCP dials/handshake probes. An endpoint is reported live only if it actually carries traffic through the tunnel.
- **WARP account registration removed.** The upstream scanner registered a fresh account on every scan via `api.cloudflareclient.com` (this failed with "error registering warp ... connection refused" where that API is unreachable). This build generates the client keypair locally and uses Cloudflare's well-known WARP public key; nothing contacts the registration API.
- UDP noise is back (default profile, or custom base64/hex/string/random packets) for ISPs that block WARP, plus the situation menu and the network-quality check that adjusts retries automatically.
- Port menu from v1.3.0 is kept: all ports (random), port 500 only, or a custom port.
- The release archive now bundles Xray-core (`core/xray`) again, so downloads are larger. Do not delete `core/` next to the scanner.
- Note: the tunnel address is IPv4-only (no registered account means no account IPv6 address). IPv6 endpoints are still genuinely tested — the handshake and traffic go to the IPv6 endpoint; only the test traffic inside the tunnel is IPv4.
