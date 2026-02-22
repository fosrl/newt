# Newt

[![PkgGoDev](https://pkg.go.dev/badge/github.com/fosrl/newt)](https://pkg.go.dev/github.com/fosrl/newt)
[![GitHub License](https://img.shields.io/github/license/fosrl/newt)](https://github.com/fosrl/newt/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/fosrl/newt)](https://goreportcard.com/report/github.com/fosrl/newt)

Newt is a fully user space [WireGuard](https://www.wireguard.com/) tunnel client and TCP/UDP proxy, designed to securely expose private resources controlled by Pangolin. By using Newt, you don't need to manage complex WireGuard tunnels and NATing.

## Installation and Documentation

Newt is used with Pangolin and Gerbil as part of the larger system. See documentation below:

- [Full Documentation](https://docs.pangolin.net/manage/sites/understanding-sites)

### Install via APT (Debian/Ubuntu)

```bash
curl -fsSL https://repo.dev.fosrl.io/apt/public.key | sudo gpg --dearmor -o /usr/share/keyrings/newt-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/newt-archive-keyring.gpg] https://repo.dev.fosrl.io/apt stable main" | sudo tee /etc/apt/sources.list.d/newt.list
sudo apt update && sudo apt install newt
```

## Key Functions

### Registers with Pangolin

Using the Newt ID and a secret, the client will make HTTP requests to Pangolin to receive a session token. Using that token, it will connect to a websocket and maintain that connection. Control messages will be sent over the websocket.

### Receives WireGuard Control Messages

When Newt receives WireGuard control messages, it will use the information encoded (endpoint, public key) to bring up a WireGuard tunnel using [netstack](https://github.com/WireGuard/wireguard-go/blob/master/tun/netstack/examples/http_server.go) fully in user space. It will ping over the tunnel to ensure the peer on the Gerbil side is brought up.

### Receives Proxy Control Messages

When Newt receives WireGuard control messages, it will use the information encoded to create a local low level TCP and UDP proxies attached to the virtual tunnel in order to relay traffic to programmed targets.

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
