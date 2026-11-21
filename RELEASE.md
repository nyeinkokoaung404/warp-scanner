# v1.3.0 — Port selection and real WireGuard probing

- New port menu: scan all ports (random, as before), port 500 only, or a custom port. Port 500 endpoints are now all `:500`.
- WARP is a WireGuard (UDP) service, so a TCP dial alone can miss live endpoints: nothing listens on TCP on a WARP port. When all TCP attempts fail, the scanner now sends a genuine WireGuard handshake initiation (Noise_IK, encrypted to Cloudflare's well-known WARP public key) and counts a valid handshake response as live. Only a real WARP server can answer it.
- Fixes empty results on networks where TCP to WARP ports is refused or filtered but the WireGuard service itself is reachable.
- The flow is now: scan mode → IP version → port → results.
