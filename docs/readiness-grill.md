# Donino readiness — Grill Me decision log

Date: 2026-10-10
Status: discovery in progress; not a production readiness declaration.

## Confirmed by the operator

- Required first-use traffic: browsing, downloads, video, games and calls.
- UDP is required, not optional.
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

1. How users enter: existing Xray/sing-box or Pasarguard service, or direct TCP/UDP port forwarding?
2. Server CPU/RAM and OS for the capacity acceptance profile.
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
