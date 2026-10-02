# ==============================================================================
# RiftRoute Phase 4 Relay Daemon — Hardened Minimal Container Image
# ==============================================================================
#
# Multi-stage build providing minimal attack surface and zero live traffic
# modification capabilities. Built solely for observation and diagnostic probing.
# ==============================================================================

# Stage 1: Build binary
FROM rust:1.80-bookworm AS builder

WORKDIR /usr/src/riftroute

# Copy workspace configuration and manifests
COPY core/rust/Cargo.toml ./Cargo.toml
COPY core/rust/rift-baseline ./rift-baseline
COPY core/rust/rift-relay ./rift-relay

# Build release binary for rift-relay
RUN cargo build --release --bin rift-relay --manifest-path Cargo.toml

# Stage 2: Hardened Runtime Container
FROM debian:bookworm-slim

# Install only necessary diagnostic tools: ping (iputils) and ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group for running the relay daemon
RUN groupadd -r -g 10001 riftrelay && \
    useradd -r -u 10001 -g riftrelay -s /sbin/nologin -d /var/empty riftrelay

# Grant ping raw socket capabilities without running as root
RUN setcap cap_net_raw+ep /bin/ping

# Create configuration and identity directory owned by riftrelay
RUN mkdir -p /etc/riftroute /var/log/riftroute && \
    chown -R riftrelay:riftrelay /etc/riftroute /var/log/riftroute && \
    chmod 750 /etc/riftroute

# Copy compiled binary from builder
COPY --from=builder /usr/src/riftroute/target/release/rift-relay /usr/local/bin/rift-relay
RUN chmod 755 /usr/local/bin/rift-relay

# Run unprivileged
USER riftrelay
WORKDIR /etc/riftroute

# Expose default control port (v1 protocol)
EXPOSE 44321

# Default execution: run relay daemon reading configuration from /etc/riftroute/config.json
ENTRYPOINT ["/usr/local/bin/rift-relay"]
CMD ["run", "--config", "/etc/riftroute/config.json"]
