# syntax=docker/dockerfile:1
#
# OpenBox for OpenShell: both services in one image.
#   openbox-verdict-middleware       the door guard
#   openbox-governance-interceptor   the front desk
# The Helm chart picks one per Deployment with `command`.
#
#   docker build -t openbox-openshell .
#
# Base images are pinned by digest; Dependabot proposes updates.

FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
# The toolchain file asks for editor components the build does not need.
ENV RUSTUP_TOOLCHAIN=1.95.0
WORKDIR /src

# Dependencies first, in their own layer, so a source-only change reuses it.
COPY middleware/Cargo.toml middleware/Cargo.lock ./
RUN mkdir -p src/bin \
 && echo 'fn main() {}' > src/main.rs \
 && echo 'fn main() {}' > src/bin/openbox-governance-interceptor.rs \
 && touch src/lib.rs \
 && cargo build --release --locked --bins \
 && rm -rf src

COPY middleware/src ./src
# COPY keeps the context's mtimes, which can be older than the stub build;
# touch them so cargo rebuilds our crate instead of shipping the stubs.
RUN find src -name '*.rs' -exec touch {} + \
 && cargo build --release --locked \
      --bin openbox-verdict-middleware \
      --bin openbox-governance-interceptor \
      --bin openbox-evidence \
 && install -D -m 0755 -t /out \
      target/release/openbox-verdict-middleware \
      target/release/openbox-governance-interceptor \
      target/release/openbox-evidence

# glibc, libgcc and CA roots, no shell. Runs as 65532, the UID the chart's
# security context expects.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.source="https://github.com/OpenBox-AI/openbox-openshell" \
      org.opencontainers.image.title="openbox-openshell" \
      org.opencontainers.image.description="OpenBox governance for NVIDIA OpenShell: the door guard and the front desk" \
      org.opencontainers.image.vendor="OpenBox" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
EXPOSE 50051 50061 50062 9464
ENTRYPOINT ["openbox-verdict-middleware"]
