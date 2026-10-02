# Phase 0 Baseline Findings & Empirical Characterization

## Executive Summary
A comprehensive network baseline was conducted on the host system located in Andhra Pradesh/Telangana, India connected via Bharti Airtel Broadband/Fiber.

The motivating query is why a player observes approximately ~200 ms in PUBG PC.

---

## 1. Local Network Condition (OBSERVED)
- **Local Gateway:** `192.168.1.1` (Wi-Fi 6 Realtek RTL8852BE Adapter)
- **First-Hop Gateway RTT:** `<1 ms` (sub-millisecond)
- **ISP Broadband Network Gateway (BNG):** `223.230.16.1` (RTT: `10-11 ms`)
- **Domestic Edge Latency (Hyderabad / Chennai Cloudflare & Google):**
  - Cloudflare Anycast (1.1.1.1): Median `12.0 ms`, Jitter `1.20 ms`, Loss `0.0%`
  - Google Anycast (8.8.8.8): Median `24.0 ms`, Jitter `1.03 ms`, Loss `0.0%`

### Conclusion on First Mile:
The local network (Wi-Fi 6, ONT, and ISP first-mile fiber) is exceptionally healthy. There is zero packet loss and minimal jitter (1 ms). **The observed ~200 ms latency does NOT originate from the local router, Wi-Fi interference, or the ISP's local access network.**

---

## 2. PUBG PC ~200 ms Latency Hypotheses

| Hypothesis | Physical/Geographic Basis | Likelihood | Verification Required in Later Phases |
| :--- | :--- | :--- | :--- |
| **Matchmaking Server Location (Europe/Frankfurt)** | India to Frankfurt transit RTT via submarine cables (SMW4 / AAE-1) is physically ~130–160 ms. | HIGH | Requires capturing server IP during live match to check geo-IP. |
| **Matchmaking Server Location (North America)** | Trans-Pacific or Trans-Atlantic routing from India to NA is physically ~200–240 ms. | HIGH | If PUBG matchmaking pools players into NA West/East servers. |
| **Sub-optimal East Asia Routing (Tokyo / Seoul)** | Direct route to Tokyo should be ~90–110 ms; if routed via Europe or US (hairpinning), RTT balloons to ~200 ms. | MEDIUM | Requires traceroute to game server IP during match. |
| **Singapore Matchmaking Failure** | Singapore servers typically yield ~40–55 ms from South India. If Singapore is unavailable, the fallback server region takes over. | HIGH | Confirm if matchmaking region selection is automatic or forced. |

---

## 3. Scientific Distinctions Established
1. **Internet Baseline Latency != Application Latency:** The user has a 12 ms connection to domestic edge nodes, but game traffic to foreign datacenters follows entirely different physical fiber paths.
2. **Traceroute ICMP Deprioritization != Forwarding Delay:** Routers along the Airtel backbone (e.g. `182.79.223.41`) may rate-limit ICMP TTL exceeded responses. The diagnostic classifier successfully marked these as `Observed` or `Inconclusive` when downstream latency remained stable.
