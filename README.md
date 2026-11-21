<h1 align="center">WARP IP Scanner</h1>

A lightweight, cross-platform scanner for finding reachable Cloudflare WARP IP endpoints. The scanner probes WARP IP and port combinations directly over TCP and reports connection latency and loss rate. It does not register WARP accounts, create WireGuard configurations, or require Xray-core.

## Features

- Direct TCP reachability checks for WARP IPv4 and IPv6 endpoints.
- When TCP fails, a genuine WireGuard handshake probe (UDP) verifies the endpoint is a live WARP server.
- IPv4-only, IPv6-only, or dual-stack scanning.
- Port selection: all ports (random), port 500 only, or a custom port.
- Quick, normal, deep, and custom scan sizes.
- Three connection attempts per endpoint with a two-second timeout.
- Results sorted by average connection latency.
- CSV export to `result.csv`.
- Standalone binaries with no bundled Xray-core dependency.

## Usage

Disconnect any active VPN before scanning. On Windows, exit v2rayN or other proxy applications completely and clear any system proxy settings.

### Windows, macOS, and Linux

Download the latest archive from the [Releases page](https://github.com/nyeinkokoaung404/warp-scanner/releases/latest), extract it, and run `BPB-Warp-Scanner`.

### Android (Termux)

Install Termux from the [official GitHub releases](https://github.com/termux/termux-app/releases/latest), then run:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/nyeinkokoaung404/warp-scanner/main/install.sh)
```

The scanner saves `result.csv` in the current directory. A successful result means the endpoint accepted a direct TCP connection or answered a WireGuard handshake; it does not create or validate a VPN tunnel.

If a scan finds no live endpoints at all, the network itself may be blocking Cloudflare WARP ranges (some Myanmar ISPs do). Try the same scan from another network, or run the scanner on a VPS that can reach Cloudflare.

## Build

Go 1.24.3 or newer is required.

```bash
make build
```

The build creates a platform archive under `dist/` and contains only the scanner binary and license file.

## License

See [LICENSE](LICENSE).
