# RiftRoute: Environment Documentation

## Host
- **Operating System:** Microsoft Windows 11 Pro
- **Build:** 26200 (Version 10.0.26200.9457)
- **Architecture:** x64 (64-bit)
- **CPU:** 13th Gen Intel(R) Core(TM) i5-13450HX (4 physical cores, 8 logical processors)

## Development Tools
- **Git:** 2.53.0.windows.2 (`C:\Program Files\Git\cmd\git.exe`)
- **Rust Toolchain (`rustup`):** 1.29.1 (`C:\Users\kdear\.cargo\bin\rustup.exe`)
- **Rust Compiler (`rustc`):** 1.99.0 (b940084d7 2026-09-28)
- **Cargo:** 1.99.0 (5f94df478 2026-08-27)
- **Rust Target:** `x86_64-pc-windows-msvc` (installed & active)
- **Rust Components:** `rustfmt 1.10.0-stable`, `clippy 0.1.99`
- **MSVC Compiler (`cl.exe`):** Microsoft (R) C/C++ Optimizing Compiler Version 19.44.35229 for x64 (`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe`)
- **MSVC Linker (`link.exe`):** Microsoft (R) Incremental Linker Version 14.44.35229.0 (`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe`)
- **Visual Studio Build Tools:** 2022 v17.14.41 (`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`)
- **Windows SDK:** 10.0.22621.0, 10.0.26100.0 (Found in registry `HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots`)
- **Python:** 3.10.11 (`C:\Users\kdear\AppData\Local\Programs\Python\Python310\python.exe`)
- **pip:** 26.2.1 (`C:\Users\kdear\AppData\Local\Programs\Python\Python310\Scripts\pip.exe`)
- **Node.js:** 24.15.0 (`C:\Program Files\nodejs\node.exe`)
- **npm:** 11.12.1 (`C:\Program Files\nodejs\npm.ps1`)
- **Tauri CLI:** 2.12.1 (`@tauri-apps/cli` installed globally)
- **Microsoft Edge WebView2 Runtime:** 154.0.4258.48 (`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.48`)

## Network Tools
- **ping:** `C:\WINDOWS\system32\PING.EXE`
- **tracert:** `C:\WINDOWS\system32\TRACERT.EXE`
- **pathping:** `C:\WINDOWS\system32\PATHPING.EXE`
- **netstat:** `C:\WINDOWS\system32\NETSTAT.EXE`
- **route:** `C:\WINDOWS\system32\ROUTE.EXE`
- **iperf3:** 3.21 (`C:\Users\kdear\AppData\Local\Microsoft\WinGet\Packages\ar51an.iPerf3_Microsoft.Winget.Source_8wekyb3d8bbwe\iperf3.exe`)
- **Wireshark:** 4.6.8 (`C:\Program Files\Wireshark\Wireshark.exe`)
- **tshark:** 4.6.8 (`C:\Program Files\Wireshark\tshark.exe`)

## Deferred Infrastructure
- **Docker:** DEFERRED — required in later infrastructure phases. Not needed for Phase 0.
- **WSL2:** DEFERRED — subsystem present but distribution not configured. Deferred until Linux relay development begins.
- **PostgreSQL:** DEFERRED — required when persistent project data is introduced.
- **Redis:** DEFERRED — required in later backend/control-plane phases.

## Installation Sources
- **Rust / rustup:** Official distribution downloaded from `https://win.rustup.rs/x86_64` (SHA256 verified against `static.rust-lang.org`: `6F4BEF66261261FCB43131BE8720BAB817D403A09EDEC7455C371974B90BDB7E`).
- **MSVC Build Tools 2022:** Official Microsoft installer package (`Microsoft.VisualStudio.2022.BuildTools` v17.14.41) providing the C++ workload (`cl.exe` 19.44.35229, `link.exe` 14.44.35229.0).
- **iPerf3:** Official Windows build via `winget` package `ar51an.iPerf3` version 3.21.
- **Wireshark:** Official Wireshark Foundation MSI installer via `winget` package `WiresharkFoundation.Wireshark` version 4.6.8.
- **Tauri CLI:** Official package `@tauri-apps/cli` version 2.12.1 via `npm install -g @tauri-apps/cli`.

## Verification
- Git, Python, pip, Node, npm: Present and operational.
- Rust toolchain: Installed and functional (`rustup`, `rustc`, `cargo`, `rustfmt`, `clippy`).
- MSVC C++ Build Tools: Installed and functional (`cl.exe` 19.44.35229, `link.exe` 14.44.35229.0).
- Compiler verification: Rust source -> Cargo -> MSVC linker -> Windows executable compiled and executed successfully with exit code 0.
- Tauri tooling: `tauri --version` and `tauri info` fully passing with all green checks.
- Wireshark & tshark: Binary paths confirmed, `tshark --version` executed successfully.
- iperf3: Binary path confirmed, `iperf3 --version` executed successfully.
- Network tools: Standard Windows networking utilities confirmed operational.
- External connectivity: DNS resolution and HTTPS TCP 443 connectivity to GitHub verified.

## Warnings
- **Wireshark Npcap:** Wireshark installed without Npcap driver; live packet capture will require Npcap driver when Phase 0 capture tests begin.
- **Terminal PATH Inheritance:** User PATH additions (`.cargo\bin` and WinGet package path) are active in current scripts via explicit process path handling, but external terminal windows will need to be reopened to inherit the new registry PATH.
