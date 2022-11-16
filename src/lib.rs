//! Merkle trie implementation for Ethereum.

use std::sync::Arc;

use primitive_types::H256;

use merkle::MerkleNode;
pub use rocksdb_lib;
pub mod gc;
pub mod merkle;
pub use memory::*;
pub use mutable::*;

#[cfg(feature = "rocksdb")]
pub mod rocksdb;

mod change;
mod cache;
mod error;
mod impls;
mod memory;
mod mutable;
mod ops;

pub (crate) use ops::{insert, delete, build, get};

pub use change::Change;

type Result<T> = std::result::Result<T, error::Error>;

pub trait CachedDatabaseHandle {
    fn get(&self, key: H256) -> Vec<u8>;
}

/// An immutable database handle.
pub trait Database {
    /// Get a raw value from the database.
    fn get(&self, key: H256) -> &[u8];
}

impl<'a, T: Database> Database for &'a T {
    fn get(&self, key: H256) -> &[u8] {
        Database::get(*self, key)
    }
}
impl<T: Database> Database for Arc<T> {
    fn get(&self, key: H256) -> &[u8] {
        Database::get(self.as_ref(), key)
    }
}

/// Represents a trie that is mutable.
pub trait TrieMut {
    /// Get the root hash of the current trie.
    fn root(&self) -> H256;
    /// Insert a value to the trie.
    fn insert(&mut self, key: &[u8], value: &[u8]);
    /// Delete a value in the trie.
    fn delete(&mut self, key: &[u8]);
    /// Get a value in the trie.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}


/// Get the empty trie hash for merkle trie.
pub fn empty_trie_hash() -> H256 {
    empty_trie_hash!()
}


#[doc(hidden)]
#[macro_export]
macro_rules! empty_trie_hash {
    () => {{
        use std::str::FromStr;

        H256::from_str("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap()
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    const KECCAK_NULL_RLP: H256 = H256([
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ]);

    #[test]
    fn it_checks_macro_generates_expected_empty_hash() {
        assert_eq!(empty_trie_hash!(), KECCAK_NULL_RLP);
    }
}
