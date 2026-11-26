#!/usr/bin/env bash
# Bootstrap a cloud sandbox (Claude Code on the web, or any fresh Ubuntu box)
# for building and testing the agentpalace workspace.
#
# Idempotent: safe to re-run, and safe to use as a snapshot/setup script.
# See docs/Cloud-Environment.md for the firewall allowlist and env vars this
# script assumes are in place.
#
# Usage: bash scripts/cloud-setup.sh [--no-warm-build]
#
#   --no-warm-build   Fetch the dependencies but skip the cold `cargo check`.
#                     Use it where the setup step has a time limit: Claude Code
#                     on the web caches an environment only when its setup
#                     script finishes within roughly five minutes.

set -euo pipefail

log() { printf '==> %s\n' "$*"; }

WARM_BUILD=1
for arg in "$@"; do
	case "$arg" in
		--no-warm-build) WARM_BUILD=0 ;;
		-h | --help)
			sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
			exit 0
			;;
		*)
			echo "error: unknown argument: $arg" >&2
			echo "usage: bash scripts/cloud-setup.sh [--no-warm-build]" >&2
			exit 2
			;;
	esac
done

# Run from the repository root whatever the caller's working directory is, so
# `cargo fetch --locked` finds Cargo.lock.
cd "$(dirname "$0")/.."

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
	SUDO="sudo"
fi

# 1. System packages.
#    protobuf-compiler: required by agentpalace-storage via lancedb/lance.
#    build-essential:   rusqlite uses the `bundled` feature, so SQLite is
#                       compiled from source.
#    libssl-dev:        openssl-sys is not vendored (no openssl-src in
#                       Cargo.lock), so it links the system OpenSSL via
#                       pkg-config and needs the headers, which a minimal
#                       image carrying only the runtime does not have.
#    libdbus-1-dev:     the Linux keyring backend links dbus-1 through
#                       pkg-config (libdbus-sys in Cargo.lock); without the
#                       headers and dbus-1.pc the workspace check fails.
log "Installing system packages"
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	curl \
	git \
	libdbus-1-dev \
	libssl-dev \
	pkg-config \
	protobuf-compiler

# 2. Rust toolchain. The workspace is edition 2024 with rust-version 1.88, and
#    there is no rust-toolchain.toml, so pin stable explicitly.
if ! command -v rustup >/dev/null 2>&1; then
	log "Installing rustup"
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
		| sh -s -- -y --default-toolchain stable --profile minimal
fi

# rustup's installer writes this; sourcing it is a no-op when cargo is already
# on PATH from a previous run.
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

log "Ensuring stable toolchain with clippy and rustfmt"
rustup toolchain install stable --profile minimal --component clippy --component rustfmt
rustup default stable

MIN_RUST="1.88.0"
ACTUAL_RUST="$(rustc --version | cut -d' ' -f2)"
if [ "$(printf '%s\n%s\n' "$MIN_RUST" "$ACTUAL_RUST" | sort -V | head -n1)" != "$MIN_RUST" ]; then
	echo "error: rustc $ACTUAL_RUST is older than the required $MIN_RUST" >&2
	exit 1
fi
log "rustc $ACTUAL_RUST"

# 3. Warm the build. `cargo fetch` pulls every crate in Cargo.lock; the
#    `cargo check` that follows runs the ort-sys build script, which downloads
#    a prebuilt ONNX Runtime from cdn.pyke.io into ~/.cache/ort.pyke.io.
#    Snapshot after this so later sessions need no network for either.
log "Fetching dependencies"
cargo fetch --locked

if [ "$WARM_BUILD" -eq 1 ]; then
	log "Warming the build (this is the long pole on a cold box)"
	cargo check --workspace --all-targets --locked
else
	log "Skipping the warm build (--no-warm-build); the first cargo check in a session is cold"
fi

# Claude Code on the web keeps the result of a setup script only when it
# finishes within roughly five minutes. Report the time so that is visible.
ELAPSED="$SECONDS"
log "Cloud environment ready in ${ELAPSED}s"
if [ "$ELAPSED" -gt 300 ]; then
	log "Over five minutes: Claude Code on the web will not cache this setup."
	if [ "$WARM_BUILD" -eq 1 ]; then
		log "Pass --no-warm-build to leave the cold check to the session."
	fi
fi
