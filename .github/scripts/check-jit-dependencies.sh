#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
consumer=$(mktemp -d)
trap 'rm -rf "$consumer"' EXIT
mkdir "$consumer/src"
cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "jit-consumer-check"
version = "0.0.0"
edition = "2021"

[workspace]

[dependencies]
stackpulse-jit = { path = "$root/crates/stackpulse-jit" }
framehop = { package = "framehop-stackpulse", path = "$root/crates/framehop-stackpulse", version = "0.17.1", default-features = false, features = ["std"] }
EOF
cat > "$consumer/src/lib.rs" <<'EOF'
pub use stackpulse_jit::{FileIdentity, Mapping, MemoryReader, Registry, Symbol, Update};
pub use stackpulse_jit::fixtures::GDB_JIT_OVERLAY_SOURCE;
use std::sync::Arc;

#[derive(Clone)]
pub struct SectionData(Arc<[u8]>);
impl From<Arc<[u8]>> for SectionData {
    fn from(bytes: Arc<[u8]>) -> Self { Self(bytes) }
}
impl std::ops::Deref for SectionData {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.0 }
}
pub fn registry<P: MemoryReader>(memory: P) -> Registry<P, SectionData> {
    Registry::new(memory)
}
pub fn modules(update: Update<SectionData>) -> Box<[framehop::Module<SectionData>]> {
    match update {
        Update::Loaded { modules, .. } => modules,
        Update::Removed { .. } => Box::default(),
    }
}
EOF

# This workspace has no recorder or dev dependencies to unify features with.
cargo check --manifest-path "$consumer/Cargo.toml"
cargo tree --manifest-path "$consumer/Cargo.toml" --locked \
    --edges normal,build --prefix none > "$consumer/tree.txt"
cat "$consumer/tree.txt"
if awk '$1 ~ /^(stackpulse|perf-event-open|perf-event-open-sys|mio|nix|tokio|wholesym)$/ { found = 1 } END { exit !found }' "$consumer/tree.txt"; then
    echo 'unexpected recorder dependency in standalone JIT consumer' >&2
    exit 1
fi
