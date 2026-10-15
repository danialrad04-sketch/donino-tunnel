# Donino readiness — Grill Me decision log

Date: 2026-10-10
Status: 0.3.0 is being prepared for operator testing; real VPS/WAN acceptance remains with the operator.

Update 2026-10-15: Workspace 02 adds grouped feature pages, live capacity settings, bounded public UDP associations, Paqet UDP/stream fallback and preserved foreign UDP sockets. Existing Xray/WireGuard backends can be connected; installing a new VPN backend and managing its accounts remain outside this release. See [the current operator test guide](workspace-v03.md). The historical decisions and remaining acceptance criteria below are preserved.

## Confirmed by the operator

- Required first-use traffic: browsing, downloads, video, games and calls.
- UDP is required, not optional.
- Required user-facing protocols in the first version: both VLESS/Xray and WireGuard (operator answer to Q3).
- Q4: support connecting to existing backends and installing Xray/WireGuard on an empty server. Preserve unrelated existing services and operator credentials.
- Q5: supported and tested target operating systems are Debian 12/13 and Ubuntu 24.04. This is required scope, not a statement that every platform already passed.
- Q6: on failure/blocking of the fast UDP path, try an alternate path and prioritize connectivity even with higher latency. Continuity requires implementation and fault-injection evidence; it is not guaranteed by this decision.
- Q7: accounts, traffic quotas and subscription expiration remain managed in the existing VPN panel. Donino is responsible for installation, tunneling and monitoring, not a new subscription manager.
- Q8: target acceptance profile is 1 CPU core and 1 GiB RAM per server; resource use has priority. This target has not been load-tested. Existing BrowserLink preflight requires at least 1.5 GiB host RAM, so BrowserLink cannot be enabled in this profile under current requirements.
- Q9: implement UDP and complete tests first, then conduct a two-VPS pilot.
- Q10: run one primary carrier and one lightweight standby; other carriers are enabled by explicit operator choice.
- Q11: Iran runs only tunnel infrastructure. Foreign also hosts the existing VPN panel. The 1 GiB target must therefore account for panel/backend resource usage on foreign; actual baseline usage remains to be measured.
- Q12: 50-user acceptance workload is mixed browsing, some downloads, video, games and calls, not 50 simultaneous bulk downloads.
- Q13: existing foreign VPN panel is Pasarguard. Preserve its accounts, subscriptions, database and credentials; do not infer availability of a WireGuard provisioning API.
- Q14: when safe memory/connection capacity is reached, preserve established connections, temporarily reject new connections and show a panel warning. This is admission-control behavior; arbitrary carrier/host outages can still interrupt established traffic.
- Q15: upgrades of Donino and carrier engines are initiated by the operator, with health verification and automatic rollback on failure. No unattended update schedule is authorized.
- Initial target: up to 50 simultaneous users.
- User count is not TCP connection count; the capacity test must represent multiple flows per user.
- Existing requests remain: role-specific Iran/foreign panels, automated two-node installation, HTTP panel support.

## Current source findings

- The gateway currently accepts TCP streams with asyncio.start_server.
- Plans currently support 1–40 named TCP services.
- FRP QUIC is a carrier; it does not provide UDP input to the gateway.
- Continuum phase 1 preserves bounded TCP sockets over WSS replacement; it has no UDP adapter.
- Continuum currently allows two Iran logical sessions with 31 application flows per session plus reserved health capacity. This does not establish support for 50 users.
- Games and calls need datagram behavior and latency tests; TCP stream recovery is insufficient evidence.
- Local and CI tests do not establish real Iran WAN/DPI behavior.

## Open decisions

1. Backend installation scope settled: existing backends and installation on an empty server. Subscription management stays in the existing VPN panel; Donino must not assume ownership of its user database.
2. CPU/RAM, OS, carrier concurrency and role workload profile settled. Pending: measured foreign panel/backend baseline resource use.
3. Acceptable gameplay/call latency, loss behavior, and recovery window.
4. Scope of direct UDP versus UDP encapsulated by an existing proxy backend.
5. Operator-controlled update policy and Pasarguard identity settled. Pending: how WireGuard peer configuration is delivered without taking ownership of subscription management.

## Acceptance work after the relevant decisions

- Implement the required datagram path and integrate plan, installers, both role panels and health probes.
- Enforce bounded associations, packet size, queues, idle cleanup and backpressure/drop policy.
- Exercise UDP loss, reordering, delay, path failure and isolation between clients.
- Measure 50-user mixed load, active-flow capacity, CPU/RAM, throughput and tail latency.
- Recheck installation, upgrade, rollback, credential handling and fresh monitoring evidence.
- Run an operator-controlled real two-VPS pilot before declaring readiness for the target network.

No claim of invisibility, zero disruption, fixed speed or universal novelty is an acceptance criterion.

