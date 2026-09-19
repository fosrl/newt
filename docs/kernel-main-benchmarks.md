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

End-to-end UDP, Olm/client compatibility, browser gateway, multiple simultaneous
streams, sustained decoded playback and adverse-WAN behavior remain untested.
The measurements motivate an optional backend; they do not establish production
readiness or explain every reported streaming issue.
