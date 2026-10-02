# RiftRoute: Environment Setup Log

- **Timestamp:** 2026-10-02 14:33:50 IST
  - **Component:** Rust Toolchain (rustup)
  - **Previous State:** Missing
  - **Action:** Downloaded official `rustup-init.exe` (v1.29.1) from `https://win.rustup.rs/x86_64`
  - **Verification:** Computed SHA256 (`6F4BEF66261261FCB43131BE8720BAB817D403A09EDEC7455C371974B90BDB7E`), verified match against official release archive.
  - **Result:** Success

- **Timestamp:** 2026-10-02 14:34:48 IST
  - **Component:** Rust / Cargo / Components
  - **Previous State:** Missing
  - **Action:** Executed `rustup-init.exe -y --default-host x86_64-pc-windows-msvc --default-toolchain stable -c rustfmt,clippy`
  - **Resulting Version:** rustc 1.99.0, cargo 1.99.0, rustup 1.29.1, rustfmt 1.10.0, clippy 0.1.99
  - **Verification:** Verified via `rustup --version`, `rustc --version`, `cargo --version`, `rustup show`, `rustup target list --installed`, `cargo fmt --version`, `cargo clippy --version`
  - **Result:** Success

- **Timestamp:** 2026-10-02 14:38:07 IST
  - **Component:** iPerf3
  - **Previous State:** Missing
  - **Action:** Installed `ar51an.iPerf3` v3.21 via `winget`
  - **Resulting Version:** iPerf 3.21 (cJSON 1.7.15)
  - **Verification:** Verified binary execution at `C:\Users\kdear\AppData\Local\Microsoft\WinGet\Packages\ar51an.iPerf3_Microsoft.Winget.Source_8wekyb3d8bbwe\iperf3.exe --version`
  - **Result:** Success

- **Timestamp:** 2026-10-02 14:38:36 IST
  - **Component:** Wireshark & TShark
  - **Previous State:** Missing
  - **Action:** Installed `WiresharkFoundation.Wireshark` v4.6.8 via `winget` (MSI installer)
  - **Resulting Version:** Wireshark 4.6.8, TShark 4.6.8 (v4.6.8-0-ge677bf052328)
  - **Verification:** Verified binary execution at `C:\Program Files\Wireshark\tshark.exe --version`
  - **Warning:** Npcap driver not installed with Wireshark; needed for live packet capture in Phase 0.
  - **Result:** Success

- **Timestamp:** 2026-10-02 14:43:21 IST
  - **Component:** Tauri CLI
  - **Previous State:** Missing
  - **Action:** Installed `@tauri-apps/cli` globally via `npm install -g @tauri-apps/cli`
  - **Resulting Version:** tauri-cli 2.12.1
  - **Verification:** Verified via `tauri --version` and `tauri info`
  - **Result:** Success

- **Timestamp:** 2026-10-02 14:43:31 IST
  - **Component:** Visual Studio 2022 C++ Build Tools
  - **Previous State:** Missing
  - **Action:** Downloaded bootstrapper `vs_BuildTools.exe` (SHA256 verified) via `winget`. Attempted non-interactive execution.
  - **Resulting Version:** Not installed
  - **Verification Result:** BLOCKED. Non-elevated subshell cannot trigger administrative UAC elevation required for MSVC system installation.
  - **Warning:** Created helper script `scripts/install_msvc_buildtools.bat` for one-click elevated execution by user.
