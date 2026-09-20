pub use stackpulse_jit::fixtures::GDB_JIT_OVERLAY_SOURCE;
pub use stackpulse_jit::{FileIdentity, Mapping, MemoryReader, Registry, Symbol, Update};
use std::sync::Arc;

#[derive(Clone)]
pub struct SectionData(Arc<[u8]>);

impl From<Arc<[u8]>> for SectionData {
    fn from(bytes: Arc<[u8]>) -> Self {
        Self(bytes)
    }
}

impl std::ops::Deref for SectionData {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
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
