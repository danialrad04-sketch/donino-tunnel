# Donino Tunnel

Two-node tunnel orchestration with a Persian administration and monitoring panel.

Implemented baseline: independent FRP WSS (mutual TLS front) and QUIC paths, signed end-to-end probes, health-based failover for new TCP connections, draining, secure administrator sessions, pinned engine downloads, two-node SSH installation and rollback.

Optional experimental adapters: Paqet, BackPack WSS and legacy Backhaul WSS. Legacy Backhaul disables certificate verification upstream and is not a secure default.

A real-browser transport is being developed and tested in this project. No transport is guaranteed undetectable or immune to blocking. See the source and validation evidence in subsequent commits.
