use std::collections::HashMap;

use primitive_types::H256;

use crate::{
    build, delete, empty_trie_hash, get, insert, AnySecureTrieMut, AnyTrieMut, Change,
    FixedSecureTrieMut, FixedTrieMut, SecureTrieMut, TrieMut,
};

/// A memory-backed trie.
#[derive(Clone, Debug)]
pub struct MemoryTrieMut {
    database: HashMap<H256, Vec<u8>>,
    root: H256,
}

/// A memory-backed trie where the value is operated on a fixed RLP
/// value type.
pub type FixedMemoryTrieMut<K, V> = FixedTrieMut<MemoryTrieMut, K, V>;
/// A memory-backed trie where the key is hashed and the value is
/// operated on a fixed RLP value type.
pub type FixedSecureMemoryTrieMut<K, V> = FixedSecureTrieMut<MemoryTrieMut, K, V>;
/// A memory-backed trie where the key is hashed.
pub type SecureMemoryTrieMut = SecureTrieMut<MemoryTrieMut>;
/// A memory-backed trie where the value is operated on any RLP
/// values.
pub type AnyMemoryTrieMut = AnyTrieMut<MemoryTrieMut>;
/// A memory-backed trie where the key is hashed and the value is
/// operated on any RLP values.
pub type AnySecureMemoryTrieMut = AnySecureTrieMut<MemoryTrieMut>;

impl Default for MemoryTrieMut {
    fn default() -> Self {
        Self {
            database: HashMap::new(),
            root: empty_trie_hash!(),
        }
    }
}

impl From<MemoryTrieMut> for HashMap<H256, Vec<u8>> {
    fn from(trie: MemoryTrieMut) -> HashMap<H256, Vec<u8>> {
        trie.database
    }
}

impl TrieMut for MemoryTrieMut {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, &self.database, key, value);

        self.apply_change(change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, &self.database, key);

        self.apply_change(change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &self.database, key).map(|v| v.into())
    }
}

impl MemoryTrieMut {
    fn apply_change(&mut self, change: Change) {
        for (key, v) in &change.changes {
            if let Some(v) = v {
                self.database.insert(*key, v.clone());
            } else {
                self.database.remove(key);
            }
        }
    }

    /// Build a memory trie from a map.
    pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> Self {
        let (new_root, change) = build(map);

        let mut ret = Self::default();
        ret.apply_change(change);
        ret.root = new_root;

        ret
    }
}
