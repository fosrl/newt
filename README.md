# Newt

Newt is a fully user space [WireGuard](https://www.wireguard.com/) tunnel client and TCP/UDP proxy, designed to securely expose private resources controlled by Pangolin. By using Newt, you don't need to manage complex WireGuard tunnels and NATing.

### Installation and Documentation

Newt is used with Pangolin and Gerbil as part of the larger system. See documentation below:

-   [Installation Instructions](https://docs.fossorial.io)
-   [Full Documentation](https://docs.fossorial.io)

## Preview

<img src="public/screenshots/preview.png" alt="Preview"/>

_Sample output of a Newt container connected to Pangolin and hosting various resource target proxies._

## Key Functions

### Registers with Pangolin

Using the Newt ID and a secret, the client will make HTTP requests to Pangolin to receive a session token. Using that token, it will connect to a websocket and maintain that connection. Control messages will be sent over the websocket.

### Receives WireGuard Control Messages

When Newt receives WireGuard control messages, it will use the information encoded (endpoint, public key) to bring up a WireGuard tunnel using [netstack](https://github.com/WireGuard/wireguard-go/blob/master/tun/netstack/examples/http_server.go) fully in user space. It will ping over the tunnel to ensure the peer on the Gerbil side is brought up. 

### Receives Proxy Control Messages

When Newt receives WireGuard control messages, it will use the information encoded to create a local low level TCP and UDP proxies attached to the virtual tunnel in order to relay traffic to programmed targets.

## CLI Args

- `endpoint`: The endpoint where both Gerbil and Pangolin reside in order to connect to the websocket.
- `id`: Newt ID generated by Pangolin to identify the client.
- `secret`: A unique secret (not shared and kept private) used to authenticate the client ID with the websocket in order to receive commands. 
- `dns`: DNS server to use to resolve the endpoint
- `log-level` (optional): The log level to use. Default: INFO

Example:

```bash
./newt \
--id 31frd0uzbjvp721 \
--secret h51mmlknrvrwv8s4r1i210azhumt6isgbpyavxodibx1k2d6 \
--endpoint https://example.com
```

You can also run it with Docker compose. For example, a service in your `docker-compose.yml` might look like this using environment vars (recommended):

```yaml
services:
  newt:
    image: fosrl/newt
    container_name: newt
    restart: unless-stopped
    environment:
      - PANGOLIN_ENDPOINT=https://example.com
      - NEWT_ID=2ix2t8xk22ubpfy 
      - NEWT_SECRET=nnisrfsdfc7prqsp9ewo1dvtvci50j5uiqotez00dgap0ii2 
```

You can also pass the CLI args to the container:

```yaml
services:
  newt:
    image: fosrl/newt
    container_name: newt
    restart: unless-stopped
    command:
        - --id 31frd0uzbjvp721
        - --secret h51mmlknrvrwv8s4r1i210azhumt6isgbpyavxodibx1k2d6
        - --endpoint https://example.com
```

## Build

### Container 

Ensure Docker is installed.

```bash
make
```

### Binary

Make sure to have Go 1.23.1 installed.

```bash
make local
```

## Licensing

Newt is dual licensed under the AGPLv3 and the Fossorial Commercial license. For inquiries about commercial licensing, please contact us.

## Contributions

Please see [CONTRIBUTIONS](./CONTRIBUTING.md) in the repository for guidelines and best practices.
