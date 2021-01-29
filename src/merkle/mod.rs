//! Merkle types.

pub mod nibble;
mod node;

use self::nibble::{Nibble, NibbleSlice, NibbleType, NibbleVec};
pub use self::node::{MerkleNode, MerkleValue};
