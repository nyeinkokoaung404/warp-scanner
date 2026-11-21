<h1 align="center">WARP IP Scanner</h1>

A cross-platform scanner for finding fast, working Cloudflare WARP IP endpoints, following [BPB-Warp-Scanner](https://github.com/bia-pain-bache/BPB-Warp-Scanner) — but **without WARP account registration**. Each endpoint is tested end-to-end: a real WireGuard tunnel is built to it through Xray-core and an HTTP request is sent through the tunnel. An endpoint is reported live only if it actually carries traffic.

## Features

- End-to-end tunnel test per endpoint via Xray-core (WireGuard): only endpoints that really work are reported.
- No account registration: the client keypair is generated locally and the peer is Cloudflare's well-known WARP public key. Nothing is sent to `api.cloudflareclient.com`, so scans work on networks where the registration API is blocked.
- UDP noise (Xray-core fork feature) for ISPs that block WARP, with a default profile or a fully custom one (base64 / hex / string / random packet, delay range, up to 50 packets).
- Network quality check before scanning: measures latency, jitter and loss and adjusts retries (3/5/7) automatically.
- IPv4-only, IPv6-only, or dual-stack scanning.
- Port selection: all ports (random), port 500 only, or a custom port.
- Quick (100), normal (1000), deep (10000), and custom scan sizes; choose how many results to show.
- Results sorted by average latency, shown in a table and saved to `result.csv`.

## Notes

- The release archive bundles the Xray-core binary (`core/xray`), so the download is larger than the scan-only builds. Do not delete `core/` next to the scanner binary.
- The tunnel address is IPv4-only (`172.16.0.2/32`) because there is no registered account to provide an IPv6 address. IPv6 endpoints are still genuinely tested (the WireGuard handshake and traffic go to the IPv6 endpoint); only the test traffic inside the tunnel is IPv4.
- If a scan finds no live endpoints at all, the network itself may be blocking Cloudflare WARP ranges (some Myanmar ISPs do). Try the same scan from another network, or run the scanner on a VPS that can reach Cloudflare.

## Usage

Disconnect any active VPN before scanning. On Windows, exit v2rayN or other proxy applications completely and clear any system proxy settings.

### Windows, macOS, and Linux

Download the latest archive from the [Releases page](https://github.com/nyeinkokoaung404/warp-scanner/releases/latest), extract it, and run `BPB-Warp-Scanner`.

### Android (Termux)

Install Termux from the [official GitHub releases](https://github.com/termux/termux-app/releases/latest), then run:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/nyeinkokoaung404/warp-scanner/main/install.sh)
```

The scanner saves `result.csv` in the current directory.

## Build

Go 1.24.3 or newer is required.

```bash
make build
```

The build downloads the matching Xray-core release (bia-pain-bache/Xray-core, which carries the UDP-noise feature), builds the scanner, and creates a platform archive under `dist/` containing the scanner binary, the `core/` directory with the Xray binary, and the license file.

## License

See [LICENSE](LICENSE).
