# Orbis native engine — phase 1

Experimental Windows backend for PCYBOX Orbis.

The goal of this phase is not feature parity with the Python backend. It isolates
the hot path so the project can benchmark a native implementation without
rewriting React/Electron.

## What is native in this phase

- Npcap capture through wpcap.dll loaded at runtime
- IPv4 TCP/UDP parsing
- process attribution through GetExtendedTcpTable / GetExtendedUdpTable
- process-name lookup through QueryFullProcessImageNameW
- connection/process tables cached every 500 ms
- 50 ms update aggregation before WebSocket delivery
- compatible endpoints used by the current React frontend
- /engine/stats counters for benchmarks

This removes the Python phase-1 bottleneck where psutil.net_connections() is
enumerated for each captured packet.

## Deliberate limitations

The Rust engine does not yet implement:

- IPv6
- GeoIP / reverse DNS enrichment
- anomaly detection
- LAN ARP scanner
- microphone/camera monitoring
- persistent SQLite timeline

Those remain available when the normal Python backend is selected.

## Build on Windows

Requirements:

- Rust stable with the MSVC toolchain
- Visual Studio Build Tools / MSVC
- Npcap installed for runtime capture

From PowerShell:

    .\rust-engine\build.ps1

The binary is copied to:

    dist\rust-engine\orbis-engine.exe

## Run directly

Run an Administrator PowerShell:

    .\dist\rust-engine\orbis-engine.exe

Then inspect:

    http://127.0.0.1:8000/engine/stats
    http://127.0.0.1:8000/graph

The React frontend can use the same port and WebSocket URL as the Python backend.

## Run through Electron

Python remains the default backend.

To use Rust for one session from a clean checkout, build the frontend first:

    cd frontend
    npm install
    npm run build
    cd ..

Then launch Electron:

    $env:ORBIS_BACKEND = "rust"
    $env:ORBIS_BACKEND_LOG = "1"
    cd electron
    npm install
    npm start

To return to Python:

    Remove-Item Env:ORBIS_BACKEND -ErrorAction SilentlyContinue
    Remove-Item Env:ORBIS_BACKEND_LOG -ErrorAction SilentlyContinue

ORBIS_BACKEND_LOG=1 makes Electron inherit the engine stdout/stderr, which is
useful during phase-1 testing.

## Suggested benchmark

Use the same machine, network workload, capture duration, and UI state.

Record for both engines:

- process CPU %
- working-set RAM
- packets observed
- UI responsiveness
- dropped packets / channel drops
- update rate sent to the UI

For Rust, /engine/stats exposes:

- packets_seen
- packets_parsed
- channel_drops
- matched_local_packets
- attributed_packets
- emitted_updates
- process_table_entries
- remote_nodes / edges

The most useful ratio is emitted_updates / packets_parsed. With aggregation it
should be substantially below 1 on busy connections.
