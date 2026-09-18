# Linux kernel main tunnel

`--kernel-main` uses the Linux WireGuard kernel implementation for the main
Newt-to-Gerbil site tunnel. Newt still manages credentials, peers, resources,
target health checks, and TCP/UDP proxies. Client/Olm tunnels keep their existing
backend. No Pangolin or Gerbil protocol change is required.

| Configuration | IP stack | Main tunnel WireGuard |
| --- | --- | --- |
| Default | Userspace netstack | `wireguard-go` |
| `--native-main` | Host kernel through TUN | `wireguard-go` |
| `--kernel-main` | Linux kernel | Linux kernel |

Enable the new backend using any one of:

- CLI: `--kernel-main --interface-main newt-main`
- Environment: `USE_KERNEL_MAIN_INTERFACE=true`, optionally `INTERFACE_MAIN=newt-main`
- JSON configuration: `"kernelMain": true`, optionally `"interfaceMain": "newt-main"`

The default interface name is `pangolin`. `--kernel-main` and `--native-main`
are mutually exclusive. Unsupported platforms and missing kernel support or
permissions cause errors; there is no automatic userspace fallback. This is a
source-build feature until a release containing it is available.

The main tunnel uses an IPv4 address; its outer WireGuard UDP endpoint can be IPv4
or IPv6. Scoped endpoints (with a `%zone`) and IPv6 link-local endpoints are
rejected because the current control library does not preserve their scope ID.
This backend supports non-default IPv4 remote subnet routes. It rejects default
routes and subnets containing the local tunnel address, WireGuard
endpoint, or resolved Pangolin control endpoint, and does not replace existing
host routes. General exit-node routing is outside this mode's scope.

## Requirements and network isolation

The Linux host must provide WireGuard, either built into its kernel or as a loaded
module. Newt needs permission to manage network interfaces and routes in its
network namespace (`CAP_NET_ADMIN`), and a working `ping` executable for tunnel
health checks. The repository's Docker image includes `ping`. Its normal Docker
capabilities include `NET_RAW`, which may be needed for ping depending on the host
configuration. If you drop the default capabilities, account for this separately.

The kernel backend does not require `/dev/net/tun`, a mounted modules directory,
`SYS_MODULE`, or a privileged Docker container. Module loading belongs to the host.
For Docker inside a Proxmox LXC, the kernel is the Proxmox host's kernel. Root in
an unprivileged LXC and Docker's `NET_ADMIN` cannot override restrictions imposed
by the outer container. Verify the actual permissions before changing LXC policy;
do not make the entire LXC privileged just to run this example.

Run Newt in a dedicated Docker network namespace, as in the example below. An
actual tunnel interface participates in that namespace's routing and firewall,
and listeners bound to all addresses can also listen on the tunnel address.
Host networking broadens this exposure to host services and can cause port
conflicts. WireGuard AllowedIPs do not restrict destination ports.

The proxy connects to reachable local targets. Publishing resources this way
does not require changing their default routes or enabling general LAN forwarding.
This setup is not a replacement for a general VPN gateway for other containers.

## Docker deployment, including Docker inside Proxmox LXC

Run the following commands from the repository root on the Docker host (inside
the Docker LXC if applicable). The build uses the existing Dockerfile and its Go
toolchain; a separate local Go installation is not needed.

1. Keep the existing `wg0` tunnel and production resources running. In Pangolin,
   create a separate **Newt site**, and later a separate test hostname/resource.
   Do not reuse an existing site's credentials while another Newt instance uses
   them. Ensure the new tunnel addresses do not conflict with existing routes.

2. Check kernel support on the Linux kernel host. For Proxmox, this means the
   Proxmox host, not the LXC. If WireGuard is already working there, it is already
   available. Otherwise install a supported host kernel/module and load it there:

   ```sh
   sudo modprobe wireguard
   ```

   The Newt startup is the definitive check that the nested Docker environment
   can also create and configure the interface. `operation not permitted` points
   to capabilities or outer LXC policy; `operation not supported` can indicate
   missing kernel support. Inspect those restrictions before granting more access.

3. Copy the example credentials file, restrict its permissions, and edit it with
   the endpoint and credentials of the test site. The example's `.gitignore`
   excludes `.env`; never commit it.

   ```sh
   cp examples/kernel-main/.env.example examples/kernel-main/.env
   chmod 600 examples/kernel-main/.env
   ```

4. Validate and build the example. `config --quiet` checks the Compose file without
   printing the expanded credentials. The image is built locally as
   `newt:kernel-main`; it does not pull an upstream image that lacks this feature.

   ```sh
   docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml config --quiet
   docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml build
   docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml up -d
   docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml logs --tail=100 newt
   docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml ps
   ```

5. Add a test resource in Pangolin with a target reachable from Newt:

   - For an existing Docker service, use the Docker host's LAN IP and the service's
     published port. Check that the host firewall permits connections from Newt's
     Docker bridge.
   - To use a Docker service name instead, attach Newt to that service's existing
     user-defined Docker network. Add an `external: true` network with its actual
     `name` to the example and to Newt's service `networks` list. Services in
     unrelated Docker networks are not automatically reachable by container name.
   - For a separate LXC, use its LAN IP and service port. Moving Vaultwarden or
     another service to an LXC later only changes the Pangolin target address,
     provided routing and firewall access are available.

   Enable and configure **target health checks in Pangolin**. The example's Docker
   health check reads Newt's tunnel health file; it is not an application health
   check and does not prove that Jellyfin, Emby, or Vaultwarden is healthy.

6. Verify the actual backend from the Docker host. These commands require
   `nsenter`, `iproute2`, and `wireguard-tools` on that host/LXC. They enter only
   the container's network namespace, so the diagnostic tools do not need to be
   installed in the Newt image:

   ```sh
   newt_container_id=$(docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml ps -q newt)
   newt_container_pid=$(docker inspect --format '{{.State.Pid}}' "$newt_container_id")
   sudo nsenter --target "$newt_container_pid" --net ip -d link show dev newt-main
   sudo nsenter --target "$newt_container_pid" --net wg show newt-main
   sudo nsenter --target "$newt_container_pid" --net ip route show
   ```

   Expect an interface of type `wireguard`, an up-to-date peer handshake, and
   increasing transfer counters when using the test resource. Never use
   `wg showconf` or `wg show ... dump` in a report: those can reveal private keys.

7. After the validation below succeeds, move production resources deliberately.
   To stop the experiment while retaining the existing `wg0` access:

   ```sh
   docker compose --env-file examples/kernel-main/.env -f examples/kernel-main/docker-compose.yml down
   ```

## Routing, Headscale, and interface ownership

Check actual tunnel addresses, advertised subnets, Docker bridge subnets, and
policy routes for overlap. A Headscale control server alone does not install
Tailscale client routes. If `tailscaled` is running in a relevant network namespace,
inspect `ip rule` and `ip route show table all` there; the commonly used
`100.64.0.0/10` range may overlap addresses assigned by Pangolin. Do not change
Headscale addressing solely because both products are installed. Docker network
isolation separates route tables but does not resolve overlaps for traffic that
must traverse the affected host.

Routes are added to the main table with the tunnel address as their preferred
source. Before adding a route, Newt rejects any existing main-table route with
the exact same destination prefix, regardless of its metric. Existing routes
are not replaced. Overlapping prefixes still need attention: a more specific
route can take precedence, and policy routing can select another table. Check
the resulting route selection for every affected subnet before enabling remote
subnet routes alongside another VPN.

Newt labels its interface with an alias of the form `newt:SITE_ID:RANDOM_TOKEN`,
visible in `ip -d link show`. It refuses to reuse an interface with the requested
name, including an interface left by an earlier Newt process. Choose a distinct
name instead of pointing it at an existing `wg0`. Normal shutdown removes the
interface that Newt created. A process killed without cleanup in a persistent
network namespace can leave a stale interface. Stop Newt and verify the exact
interface's type, ownership, and namespace before manually deleting it with
`ip link delete dev INTERFACE_NAME`. Do not delete a working tunnel merely to
satisfy the name check. A dedicated Docker namespace also limits the lifetime of
such state to that namespace.

MTU defaults to 1280. Keep it constant for initial comparisons, then measure before
tuning. A successful handshake or a short HTTP request does not rule out MTU,
packet-loss, return-route, or application throughput problems.

## Validation before replacing a working tunnel

The opt-in Linux lifecycle test creates a fresh network namespace, checks a real
kernel interface, peer configuration, route updates and cleanup, then removes the
namespace. Build the test binary as the normal development user and execute it
with the necessary privileges on a Linux test machine:

```sh
mkdir -p bin
CGO_ENABLED=0 go test -c -o bin/kernelwg.test ./internal/kernelwg
sudo env NEWT_KERNEL_WG_INTEGRATION=1 ./bin/kernelwg.test -test.run '^TestLinuxKernelLifecycle$' -test.v -test.count=1
```

Creating the test namespace requires `CAP_SYS_ADMIN` in addition to
`CAP_NET_ADMIN`; `SYS_ADMIN` is **not a requirement for the Newt runtime**. A
restricted LXC may disallow this test even when ordinary kernel tunnel creation
works inside it. With the environment variable unset, the lifecycle test skips.
It does not perform a peer handshake or exercise Pangolin or streaming.

The repository's [test workflow](../.github/workflows/test.yml) also builds and
runs this lifecycle test under `sudo` on its Ubuntu runner, using the isolated
network namespace. A passing workflow establishes the tested kernel lifecycle;
the application and performance checks below still require a real deployment.

Automated unit tests and cross-compilation alone cannot establish kernel
functionality or streaming performance. In addition to the lifecycle test, run
these integration checks against a test Pangolin/Gerbil instance on Linux:

- Connect, confirm the kernel device and handshake, access TCP and UDP resources,
  and observe target health transitions when a test target stops and starts.
- Update a target and any remote subnets, restart Newt, and interrupt/recover the
  tunnel. Confirm reconnect and clean interface removal after a normal stop.
- Verify failure behavior for an existing interface name and insufficient
  permissions without disturbing other interfaces or routes.
- Compare the existing direct `wg0` path, normal Newt, native-main, and kernel-main
  on the same endpoints and network path where possible. Record MTU, CPU usage,
  and whether TLS/proxy layers differ; a raw WireGuard result is not by itself an
  equivalent application-path benchmark.
- Measure a single sustained TCP transfer as well as parallel transfers, in both
  directions. Play the same high-bitrate media long enough to exercise buffering
  and seeking. Observe host CPU usage as well as the Newt process: kernel work is
  not fully attributed to Newt.

Kernel WireGuard can reduce userspace networking overhead, but Newt still proxies
traffic and the rest of the path still matters. No particular throughput increase
is guaranteed. macOS/Windows builds can validate compatibility; they cannot
validate this Linux-only backend.
