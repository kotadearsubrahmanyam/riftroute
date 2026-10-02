# RiftRoute: Future Work & Unresolved Discoveries

This document records requirements, observations, and dependencies identified during development that are explicitly out-of-scope for the current phase, as governed by Section 2 and Section 36 of the Master AI Builder Prompt.

---

## 1. Dynamic Game Server IP & UDP Match Capture
- **Discovery:** In competitive FPS games (PUBG PC, CS2, VALORANT), initial connection to lobby/matchmaking occurs over TCP/HTTPS, while in-game match simulation traffic switches to high-frequency UDP ports (e.g., ports 7000–8999).
- **Reason It Matters:** Determining exact game server IP and port during match play requires continuous socket sampling or packet inspection.
- **Dependency:** Phase 1 (Traffic Classification & Network Measurement Engine).
- **Recommended Future Phase:** Phase 1 & Phase 2.
- **Blocks Current Work:** No.

## 2. Live Packet Capture & Npcap Driver
- **Discovery:** While Windows socket APIs (`netstat` / `GetExtendedTcpTable` / `GetExtendedUdpTable`) detect endpoints, they do not report per-packet latency or in-flight jitter of UDP streams.
- **Reason It Matters:** Wireshark/tshark was installed without the Npcap driver to avoid kernel-level driver installation during read-only Phase 0.
- **Dependency:** User authorization for Npcap driver installation.
- **Recommended Future Phase:** Phase 1 (when deep packet inspection is required).
- **Blocks Current Work:** No.

## 3. Dedicated Relay Infrastructure for International Routing
- **Discovery:** The user's domestic ISP path to Indian servers is ~10–12 ms, but international routes to PUBG servers show ~200 ms latency due to subsea cable hops and distant server placement.
- **Reason It Matters:** Routing optimization cannot change physics or server placement, but can bypass congested or sub-optimal transit routes by tunneling via low-latency cloud relays (e.g. Mumbai -> Singapore or Chennai -> Frankfurt).
- **Dependency:** Phase 3 (Relay Architecture & Tunnel Management).
- **Recommended Future Phase:** Phase 3 & Phase 4.
- **Blocks Current Work:** No.

## 4. Multi-Region Gaming Latency Catalog
- **Discovery:** PUBG PC and other FPS games do not publish static server IP ranges; servers are dynamically spun up on cloud providers (AWS, Azure, Tencent Cloud).
- **Reason It Matters:** A curated, validated database of cloud datacenter endpoints (Mumbai, Singapore, Tokyo, Seoul, Frankfurt, Bahrain) is needed for continuous reference benchmarking.
- **Dependency:** Phase 1 Network Measurement Engine.
- **Recommended Future Phase:** Phase 1.
- **Blocks Current Work:** No.
