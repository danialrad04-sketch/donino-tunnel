# Donino readiness — Grill Me decision log

Date: 2026-10-10
Status: discovery in progress; not a production readiness declaration.

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
2. CPU/RAM and OS profile settled. Pending: carrier concurrency in the low-memory profile and whether the 1 GiB budget includes the existing VPN panel and backends.
3. Acceptable gameplay/call latency, loss behavior, and recovery window.
4. Scope of direct UDP versus UDP encapsulated by an existing proxy backend.

## Acceptance work after the relevant decisions

- Implement the required datagram path and integrate plan, installers, both role panels and health probes.
- Enforce bounded associations, packet size, queues, idle cleanup and backpressure/drop policy.
- Exercise UDP loss, reordering, delay, path failure and isolation between clients.
- Measure 50-user mixed load, active-flow capacity, CPU/RAM, throughput and tail latency.
- Recheck installation, upgrade, rollback, credential handling and fresh monitoring evidence.
- Run an operator-controlled real two-VPS pilot before declaring readiness for the target network.

No claim of invisibility, zero disruption, fixed speed or universal novelty is an acceptance criterion.

