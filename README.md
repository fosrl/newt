# Newt
[![PkgGoDev](https://pkg.go.dev/badge/github.com/fosrl/newt)](https://pkg.go.dev/github.com/fosrl/newt)
[![GitHub License](https://img.shields.io/github/license/fosrl/newt)](https://github.com/fosrl/newt/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/fosrl/newt)](https://goreportcard.com/report/github.com/fosrl/newt)

Newt is a fully user space [WireGuard](https://www.wireguard.com/) tunnel client and TCP/UDP proxy, designed to securely expose private resources controlled by Pangolin. By using Newt, you don't need to manage complex WireGuard tunnels and NATing.

### Installation and Documentation

Newt is used with Pangolin and Gerbil as part of the larger system. See documentation below:

-   [Full Documentation](https://docs.pangolin.net/manage/sites/understanding-sites)

## Key Functions

### Registers with Pangolin

Using the Newt ID and a secret, the client will make HTTP requests to Pangolin to receive a session token. Using that token, it will connect to a websocket and maintain that connection. Control messages will be sent over the websocket.

### Receives WireGuard Control Messages

When Newt receives WireGuard control messages, it will use the information encoded (endpoint, public key) to bring up a WireGuard tunnel using [netstack](https://github.com/WireGuard/wireguard-go/blob/master/tun/netstack/examples/http_server.go) fully in user space. It will ping over the tunnel to ensure the peer on the Gerbil side is brought up.

### Receives Proxy Control Messages

When Newt receives WireGuard control messages, it will use the information encoded to create a local low level TCP and UDP proxies attached to the virtual tunnel in order to relay traffic to programmed targets.

### DNS Authority

Newt includes an authoritative DNS server that can serve customized DNS records for specific domains (zones) managed by Pangolin. This allows for intelligent routing and high-availability setups where Newt can respond with the healthiest target IPs for a given service.

The DNS server runs on port 53 (UDP/TCP). By default, it binds to `0.0.0.0`, but this can be customized using the `--dns-bind` flag or `DNS_BIND_ADDR` environment variable.

#### systemd-resolved Conflict

On many modern Linux distributions, `systemd-resolved` binds to `127.0.0.53:53`, which prevents Newt from binding to `0.0.0.0:53`. To resolve this, you can:
1.  Disable `systemd-resolved`: `sudo systemctl disable --now systemd-resolved`
2.  Or bind Newt to a specific public IP that doesn't conflict with the loopback address used by resolved: `--dns-bind 1.2.3.4`
3.  Or disable the DNS Authority feature entirely if you don't need it: `--disable-dns-authority`

## Configuration

Newt can be configured via environment variables or command-line flags.

| Environment Variable | Flag | Description | Default |
|----------------------|------|-------------|---------|
| `PANGOLIN_ENDPOINT` | `--endpoint` | Pangolin server endpoint | |
| `NEWT_ID` | `--id` | Newt Site ID | |
| `NEWT_SECRET` | `--secret` | Newt Site Secret | |
| `DNS_BIND_ADDR` | `--dns-bind` | Bind address for DNS Authority | `0.0.0.0` |
| `DISABLE_DNS_AUTHORITY` | `--disable-dns-authority` | Disable the DNS Authority server | `false` |
| `LOG_LEVEL` | `--log-level` | Logging level (DEBUG, INFO, WARN, ERROR, FATAL) | `INFO` |

## Build

### Binary

Make sure to have Go 1.25 installed.

```bash
make
```

### Nix Flake

```bash
nix build
```

Binary will be at `./result/bin/newt`

Development shell available with `nix develop`

## Licensing

Newt is dual licensed under the AGPLv3 and the Fossorial Commercial license. For inquiries about commercial licensing, please contact us.

## Contributions

Please see [CONTRIBUTIONS](./CONTRIBUTING.md) in the repository for guidelines and best practices.
