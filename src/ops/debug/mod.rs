use crate::cache::AsyncCachedHandle;
use crate::gc::MapWithCounter;
use std::sync::Arc;

mod draw;

#[cfg(test)]
mod hex_input;

pub mod child_extractor;

pub use draw::{draw, Child, DebugPrintExt};

#[cfg(test)]
pub use hex_input::EntriesHex;

pub type MapWithCounterCached = AsyncCachedHandle<Arc<MapWithCounter>>;
