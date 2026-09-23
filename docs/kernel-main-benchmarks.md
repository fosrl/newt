# Exploratory kernel-main measurements

Measured on 2026-09-18, at commit `990901e`, before the subsequent PR-review
hardening changes. These are observations from one deployment, not performance
guarantees. The later code-review fixes were unit-tested separately; this media
benchmark was not repeated after those fixes.

## Setup and method

- Intel Core i3-13100 (4 cores / 8 threads), Linux `7.0.14-8-pve`, Docker inside
  a Proxmox LXC, Pangolin EE `1.22.1` on a remote VPS, MTU 1280 in every Newt mode.
- The same custom binary ran in default, native-main and kernel-main modes.
  Stock Newt `1.17.0` and an existing direct WireGuard tunnel were references.
- A real Jellyfin media file was transferred from its authenticated static-file
  endpoint to a receiver in Gerbil's network namespace. Bytes were discarded;
  no player, decoding or transcoding was involved. Public TLS/reverse-proxy
  layers and the viewer's connection were outside the measurement path.
- Topology: Jellyfin ran on the LAN, one hop from the Docker host. Newt ran in
  the bridge network of the example Compose file: no host networking, no
  ipvlan, no hairpin through a published port. Traffic left the site over a
  residential WAN link to the VPS. Every mode, including the direct WireGuard
  reference, was capped by that link's upstream capacity of roughly 34 Mbit/s.
  **The throughput column therefore measures the uplink, not the tunnel.** The
  comparison of interest is CPU per GiB transferred.
- Each main comparison lasted 60 seconds, capped at 512 MiB. Userspace and kernel
  runs alternated in A–B–B–A order. Native-main and direct-WireGuard references
  were separate runs; the direct reference lasted 30 seconds.
- Host `/proc/stat` and Newt cgroup CPU counters were sampled once per second,
  with background-load windows before and after. CPU calculations used 57
  seconds wholly inside each 60-second transfer, excluding the edges. Byte
  counts at window boundaries were interpolated. Clocks were NTP-synchronized.
- CPU measurements include Newt control/health work; no idle subtraction was
  applied. No cgroup CPU-quota throttling was observed.

## Single-stream results

| Mode | Throughput (Mbit/s) | Newt cgroup CPU (% of one logical CPU) | Newt cgroup CPU-seconds/GiB | Time to receive 16 MiB (s) |
| --- | ---: | ---: | ---: | ---: |
| Stock Newt 1.17.0 | 32.885 | 75.33 | 196.13 | 4.269 |
| Same binary, userspace A1 | 32.804 | 66.95 | 175.05 | 4.262 |
| Same binary, kernel B1 | 33.683 | 0.96 | 2.44 | 4.091 |
| Same binary, kernel B2 | 33.452 | 0.99 | 2.53 | 4.479 |
| Same binary, userspace A2 | 32.797 | 67.86 | 177.60 | 4.204 |
| Same binary, native-main | 33.724 | 40.34 | 102.53 | 4.118 |
| Existing direct WireGuard, 30 s | 33.771 | N/A | N/A | 4.035 |

**The cgroup does not account for all kernel workers and softIRQs.** Its large
CPU decrease must not be described as an equivalent decrease in whole-host CPU
or power. Whole-host CPU was also sampled, but unrelated load varied too much
for precise attribution: total host utilization was 20.68% in kernel B1 and
34.86% in B2 while Newt's cgroup CPU stayed almost identical.

There was no material demonstrated throughput improvement on this path, and
none could be shown: the residential uplink capped every run at about 34 Mbit/s,
including the direct WireGuard reference. Behavior on a saturated link,
parallel streams and long-running iperf3 sessions remain to be measured on a
LAN-local Pangolin/Gerbil test instance where the WAN drops out of the path.

## Startup, power and limitations

Bounded 4-MiB Range requests succeeded. The initial stock-Newt requests took
1.801–2.652 seconds, but a later stock repeat took 1.119–1.128 seconds, compared
with 1.061–1.128 seconds for kernel-main. Cache, order and background load are
confounders. A general improvement in player startup or seeking is not proven.

Two additional 30-second samples observed CPU-package RAPL averages of 3.508 W
(userspace) and 2.703 W (kernel), at approximately 32.52 and 33.85 Mbit/s.
Adjacent background averages ranged from 2.56 to 2.87 W. This is an exploratory
CPU-package observation, not wall-power measurement or a guaranteed 0.80 W
system saving. Kernel work still consumes energy. RAPL domains are hierarchical
and were not summed; see the [Linux powercap documentation](https://docs.kernel.org/power/powercap/powercap.html).

Separate functional checks confirmed a real `wireguard` interface, TCP resource
access, target health transitions, Newt restart, and interface removal after a
normal stop while a helper kept the network namespace alive. All temporary test
resources were removed without changing production tunnels or services.

Olm/client compatibility, browser gateway, sustained decoded playback and
adverse-WAN behavior remain untested. The measurements motivate an optional
backend; they do not establish production readiness or explain every reported
streaming issue.

## LAN benchmark: Gerbil and Newt on one Proxmox host

Measured on 2026-09-19 at commit `ca6fce0`. This run answers the review request
for a network that can saturate itself, iperf3 instead of file downloads, single
and parallel streams, and a long run with additional streams stacked on top. It
complements the WAN run above; absolute numbers are specific to this host.

### Topology

Everything sits on a single Proxmox host (kernel `7.0.14-8-pve`, 8 threads):

- Pangolin 1.23.0, Gerbil 1.5.2 and Traefik v3.7 in a fresh Ubuntu 24.04 VM
  (4 vCPU, virtio NIC on the host bridge). Gerbil's `wg0` is Linux kernel
  WireGuard in the VM kernel (6.8). Pangolin ran over plain HTTP on the LAN.
- Newt in a Docker container inside an unprivileged LXC on the same host,
  attached to a Docker bridge network (not host networking), MTU 1280. The
  iperf3 server runs on the LXC's own address; Newt proxies to it over the
  Docker bridge. No hairpin, no physical NIC, no WAN.
- The iperf3 client runs inside the Gerbil container's network namespace and
  connects to Newt's tunnel address and the per-resource proxy port. Traefik is
  not in this path.

Both endpoints are connected by a Linux bridge in the hypervisor kernel, so
every hop is a memory copy. The path saturates on CPU, not on a link, and no
NIC offload participates. Gerbil's namespace clamps TCP MSS to 1240 on `wg0`
and drops unsolicited inbound traffic other than ICMP echo and TCP 80/443,
which matters for anyone reproducing this.

### Method

- iperf3 3.16 client, 3.20 server, 60 s per run, receiver-side throughput.
- Single stream in both directions, ten parallel streams in both directions.
  Single-stream order userspace, kernel, kernel, userspace (A-B-B-A); native
  once.
- CPU sampled once per second: Newt container cgroup, the LXC cgroup and the
  whole host on the Proxmox host, and the Gerbil VM cgroup. CPU seconds per
  received GiB, no idle subtraction. About fifty other containers ran in the
  same LXC; two of them (a media server and a file sync daemon) became busy
  midway through, which raises host and LXC totals for later runs. The Newt
  cgroup is unaffected by that.
- Kernel WireGuard work runs in kernel worker threads outside the container
  cgroup; only the host total captures it.

### Results (Mbit/s, receiver; CPU-s per GiB)

| Test | userspace | kernel | native |
| --- | --- | --- | --- |
| 1 stream, Gerbil → Newt | 456 / 399 | 563 / 519 | 406 |
| 1 stream, Newt → Gerbil (`-R`) | 195 / 165 | 313 / 281 | 815 |
| 10 streams, Gerbil → Newt | 442 | 320 | 228 |
| 10 streams, Newt → Gerbil | 176 | 272 | 806 |
| Newt cgroup CPU-s/GiB, Gerbil → Newt | 47–53 | 5.0–5.1 | 35 |
| Newt cgroup CPU-s/GiB, Newt → Gerbil | 100–110 | 1.5–1.7 | 11 |

Host-total CPU per GiB, corrected only roughly for background load measured in
a 60 s idle window before each block: about 60 CPU-s/GiB for kernel and about
100 CPU-s/GiB for userspace in the Gerbil → Newt direction. Treat this as an
estimate; background load varied by more than 100 CPU-s per minute.

UDP through the Newt UDP proxy, iperf2 with 1200-byte datagrams, 10 s, single
runs, server bound to the target address: loss-free at 10 and 50 Mbit/s in all
three modes; at 200 Mbit/s (about 21 800 pps) loss was 8.6 % (userspace), 19 %
(kernel) and 1.1 % (native). A tendency, not a ranking.

### Sustained run with stacked load (30 min, Newt → Gerbil single stream)

Main stream: one `-R` stream for 30 minutes. After 10 minutes, five forward
streams were added for 5 minutes on a second resource; after 20 minutes a
single forward stream limited to 50 Mbit/s for 5 minutes.

| | userspace | kernel |
| --- | --- | --- |
| main stream alone (min 1–9) | 160–190 Mbit/s | 324–332 Mbit/s |
| main stream with 5 extra streams | 74–87 (−60 %) | 274–294 (−12 to −17 %) |
| main stream after they stop | 194–197 | 297–321 |
| main stream with a 50 Mbit/s extra stream | 164–182 | 248–314 |
| 30 min average, main stream | 165 Mbit/s (34.6 GiB) | 307 Mbit/s (64.3 GiB) |
| retransmits, main stream, 30 min | 1 427 | 13 782 |
| Newt cgroup, main stream alone | 125–150 CPU-s/min | 3.3 CPU-s/min |
| Newt cgroup, whole run | 121 CPU-s/GiB | 3.0 CPU-s/GiB |

Neither mode flatlined or degraded over time; both recovered fully when the
extra streams stopped. In userspace mode the Newt process was CPU-saturated at
about 2.3 cores, so the extra streams took 60 % of the main stream. In kernel
mode the process stayed almost idle and the main stream lost 12 to 17 %.

### Observations and caveats

- Kernel mode removes WireGuard and IP-stack work from the Newt process; the
  Newt cgroup drops by one to two orders of magnitude. Part of that work moves
  to the kernel and is still paid on the host.
- Ten parallel streams did not exceed a single stream in any mode.
- Retransmits occur in every mode on a loss-free bridge path; they indicate
  queueing inside the path, not network loss.
- **Open item: the Newt → Gerbil direction of kernel mode.** It is faster than
  userspace but clearly slower than native on this host. The proxy is not the
  cause: iperf3 directly between the tunnel endpoints (server in the Newt
  namespace, client in the Gerbil namespace, no proxy) gives 317 Mbit/s for
  kernel mode against 1822 Mbit/s for native, matching the 281–313 Mbit/s seen
  through the proxy, while Gerbil → Newt is 567 against 454 in favour of kernel
  mode. `ss -ti` on the sending socket shows 2–3 MB not yet sent, a congestion
  window of 950–2000 segments and RTT inflated from 0.26 ms to 6–32 ms at
  230–315 Mbit/s delivery rate, with zero drops on the interface. The queueing
  happens inside the kernel WireGuard send path out of the Docker namespace in
  an unprivileged LXC, not in TCP or the proxy. The cause was not investigated
  further; candidates are the single-queue device, crypto worker scheduling on
  the hypervisor kernel, and the outer UDP stream crossing bridge NAT without
  GSO.
- A first UDP attempt reported only the first datagram of each flow arriving.
  That was a test artefact, reproduced identically with stock Newt 1.17.0: the
  target was the LXC's own address reached over the Docker bridge, the UDP
  server answered from the bridge address, and Newt's connected target socket
  discarded those replies (`NoPorts` in `/proc/net/snmp` rose by one per
  datagram). Binding the server to the target address removed the loss. Not a
  Newt problem, but worth knowing when a UDP target listens on a wildcard
  address behind a bridge.
