# v1.4.2 — Dual-stack tunnel: IPv6 address + reserved bytes

Live tests of v1.4.0/v1.4.1 returned 0 endpoints on both VPS and Termux, with
every failure a tunnel timeout — even with UDP noise OFF. The remaining
structural difference from a plain WARP WireGuard config (which connects
fine to the same endpoint) was the tunnel address: the scanner used an
IPv4-only address with no reserved bytes, while every working WARP config
carries an IPv6 address and reserved 0,0,0.

- The tunnel is now dual-stack: the standard unregistered IPv4 address
  (172.16.0.2/32) plus a random address from Cloudflare's WARP client range
  2606:4700:110::/48, and the standard reserved bytes 0,0,0 — exactly like a
  plain WARP WireGuard config. Still no account registration: the keypair
  and the IPv6 address are generated locally, the peer is Cloudflare's
  well-known WARP public key, and nothing contacts api.cloudflareclient.com.
- The DNS query strategy follows the scan mode again (UseIPv4 / UseIPv6 /
  UseIP), as upstream does, and the test-target resolution picks the matching
  address family.
