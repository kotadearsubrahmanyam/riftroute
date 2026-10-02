# RiftRoute: Environment Readiness Matrix

| Requirement | Status | Version | Mandatory Now | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **Windows x64** | **PASS** | 10.0.26200 (x64) | YES | `Win32_OperatingSystem` query verified 64-bit architecture |
| **Git** | **PASS** | 2.53.0.windows.2 | YES | `C:\Program Files\Git\cmd\git.exe` operational |
| **Rust (`rustc`)** | **PASS** | 1.99.0 | YES | `rustc --version` verified (`stable-x86_64-pc-windows-msvc`) |
| **Cargo** | **PASS** | 1.99.0 | YES | `cargo --version` verified |
| **MSVC (`cl.exe` / `link.exe`)** | **PASS** | 19.44.35229 / 14.44.35229.0 | YES | `cl.exe` and `link.exe` operational; VS Build Tools 17.14.41 detected |
| **Windows SDK** | **PASS** | 10.0.26100.0 | YES | Registered in `HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots` |
| **Tauri Prerequisites** | **PASS** | 2.12.1 | YES | `tauri-cli 2.12.1` installed; `tauri info` reports all components verified |
| **Python** | **PASS** | 3.10.11 | YES | `python --version` verified |
| **Node.js** | **PASS** | 24.15.0 | YES | `node --version` verified |
| **npm** | **PASS** | 11.12.1 | YES | `npm --version` verified |
| **Wireshark / tshark** | **PASS** | 4.6.8 | YES | `tshark.exe --version` verified |
| **iperf3** | **PASS** | 3.21 | YES | `iperf3.exe --version` verified |
| **Docker** | **DEFERRED** | N/A | NO | DEFERRED — required in later infrastructure phases |
| **WSL2** | **DEFERRED** | Subsystem present | NO | DEFERRED — required when Linux relay development begins |
| **PostgreSQL** | **DEFERRED** | N/A | NO | DEFERRED — required when persistent project data is introduced |
| **Redis** | **DEFERRED** | N/A | NO | DEFERRED — required in later backend/control-plane phases |

---

## Readiness Scoring

$$\text{Readiness} = \frac{\text{Mandatory Checks Passed}}{\text{Mandatory Checks Required}} \times 100 = \frac{12}{12} \times 100 = 100.0\%$$

- **Mandatory Requirements Total:** 12
- **Mandatory Requirements Passed:** 12
- **Mandatory Requirements Blocked:** 0
- **Deferred Non-Blocking Requirements:** 4 (Docker, WSL2, PostgreSQL, Redis)
- **Readiness Score:** 100.0%
- **Environment Gate:** **READY**
