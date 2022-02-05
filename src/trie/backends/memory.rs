#![allow(unused)] // FIXME: delete this line

use std::{
    borrow::Cow,
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    sync::Arc,
};

use dashmap::{mapref::entry::Entry, DashMap};
use derivative::*;
use log::trace;
use primitive_types::H256;
use rlp::Rlp;

use crate::{
    cache::CachedHandle,
    database::{Database, DatabaseMut},
    empty_trie_hash,
    merkle::{MerkleNode, MerkleValue},
    CachedDatabaseHandle,
};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct ReachableHashes<F> {
    childs: Vec<H256>,
    #[derivative(Debug = "ignore")]
    child_extractor: F,
}

impl<F> ReachableHashes<F>
where
    F: FnMut(&[u8]) -> Vec<H256>,
{
    pub fn collect(merkle_node: &MerkleNode, child_extractor: F) -> Self {
        let mut this = Self {
            childs: Default::default(),
            child_extractor,
        };
        this.process_node(merkle_node);
        this
    }

    fn process_node(&mut self, merkle_node: &MerkleNode) {
        match merkle_node {
            MerkleNode::Leaf(_, d) => self.childs.extend_from_slice(&(self.child_extractor)(*d)),
            MerkleNode::Extension(_, merkle_value) => {
                self.process_value(merkle_value);
            }
            MerkleNode::Branch(merkle_values, data) => {
                if let Some(d) = data {
                    self.childs.extend_from_slice(&(self.child_extractor)(*d))
                }
                for merkle_value in merkle_values {
                    self.process_value(merkle_value);
                }
            }
        }
    }

    fn process_value(&mut self, merkle_value: &MerkleValue) {
        match merkle_value {
            MerkleValue::Empty => {}
            MerkleValue::Full(merkle_node) => self.process_node(merkle_node),
            MerkleValue::Hash(hash) => self.childs.push(*hash),
        }
    }

    pub fn childs(self) -> Vec<H256> {
        self.childs
            .into_iter()
            // Empty trie is a common default value for most
            // objects that contain submap, filtering it will reduce collissions.
            .filter(|i| *i != empty_trie_hash!())
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct MemoryBackend {
    counter: DashMap<H256, usize>,
    data: DashMap<H256, Vec<u8>>,
}

impl MemoryBackend {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn increase(&self, key: H256) -> usize {
        self.counter
            .entry(key)
            .and_modify(|count| {
                *count += 1;
            })
            .or_insert(1);
        trace!("{} count++ is {}", key, *self.counter.get(&key).unwrap());
        *self.counter.get(&key).unwrap()
    }

    fn decrease(&self, key: H256) -> usize {
        let count = match self.counter.entry(key) {
            Entry::Vacant(_) => unreachable!(),
            Entry::Occupied(entry) if *entry.get() <= 1 => {
                entry.remove();
                0
            }
            Entry::Occupied(mut entry) => {
                *entry.get_mut() -= 1;
                *entry.get()
            }
        };
        trace!("{} count-- is {}", key, count);
        count
    }
}

// TODO: Review impl pls
impl CachedDatabaseHandle for Arc<MemoryBackend> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.data
            .get(&key)
            .map(|x| x.value().clone())
            .unwrap()
            .to_vec()
    }
}

impl DatabaseMut for CachedHandle<Arc<MemoryBackend>> {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        match self.db.data.entry(key) {
            Entry::Occupied(_) => {}
            Entry::Vacant(v) => {
                let rlp = Rlp::new(value);
                let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                trace!("inserting node {}=>{:?}", key, node);
                for hash in ReachableHashes::collect(&node, child_extractor).childs() {
                    self.db.increase(hash);
                }
                v.insert(value.to_vec());
            }
        };
    }
    fn gc_count(&self, key: H256) -> usize {
        self.db.counter.get(&key).map(|v| *v).unwrap_or_default()
    }

    // Return true if node data is exist, and it counter more than 0;
    fn node_exist(&self, key: H256) -> bool {
        self.db.data.get(&key).is_some() && self.gc_count(key) > 0
    }

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node<F>(&self, key: H256, child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        match self.db.data.entry(key) {
            Entry::Occupied(entry) if self.gc_count(key) == 0 => {
                // in this code we lock data, so it's okay to check counter from separate function
                let value = entry.remove();
                let rlp = Rlp::new(&value);
                let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");

                ReachableHashes::collect(&node, child_extractor)
                    .childs()
                    .into_iter()
                    .filter(|k| self.db.decrease(*k) == 0)
                    .collect()
            }
            _ => vec![],
        }
    }

    fn gc_pin_root(&self, key: H256) {
        self.db.increase(key);
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        self.db.decrease(key) == 0
    }
}

#[cfg(test)]
mod tests {
    use crate::{empty_trie_hash, trie::TrieHandle};

    use super::*;
    use hex_literal::hex;
    use std::str::FromStr;

    fn dummy_extractor(data: &[u8]) -> Vec<H256> {
        vec![]
    }

    #[test]
    fn trie_middle_leaf() {
        let mut map = HashMap::new();
        map.insert(
            "key1aa".as_bytes().to_vec(),
            "0123456789012345678901234567890123456789xxx"
                .as_bytes()
                .to_vec(),
        );
        map.insert(
            "key1".as_bytes().to_vec(),
            "0123456789012345678901234567890123456789Very_Long"
                .as_bytes()
                .to_vec(),
        );
        map.insert("key2bb".as_bytes().to_vec(), "aval3".as_bytes().to_vec());
        map.insert("key2".as_bytes().to_vec(), "short".as_bytes().to_vec());
        map.insert("key3cc".as_bytes().to_vec(), "aval3".as_bytes().to_vec());
        map.insert(
            "key3".as_bytes().to_vec(),
            "1234567890123456789012345678901".as_bytes().to_vec(),
        );

        let btrie =
            TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::build(&map, |data: &[u8]| vec![]);

        assert_eq!(
            btrie.root(),
            H256::from_str("cb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89")
                .unwrap()
        );
        assert_eq!(
            btrie.get("key2bb".as_bytes(), dummy_extractor),
            Some("aval3".as_bytes().to_vec())
        );
        assert_eq!(btrie.get("key2bbb".as_bytes(), dummy_extractor), None);

        let mut mtrie = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();
        for (key, value) in &map {
            mtrie.insert(key, value, dummy_extractor);
        }

        dbg!(&btrie.database());
        dbg!(&mtrie.database());

        // assert_eq!(btrie.database(), mtrie.database()); // FIXME: uncomment?

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes(), dummy_extractor);
        mtrie.delete("key2bbb".as_bytes(), |_| vec![]);

        // assert_eq!(btrie.database(), mtrie.database()); // FIXME: uncomment?

        for key in map.keys() {
            mtrie.delete(key, |_| vec![]);
        }

        // assert!(mtrie.database().is_empty()); // FIXME: uncomment?
        assert!(mtrie.root == empty_trie_hash!());
    }

    #[test]
    fn trie_two_keys() {
        let mut mtrie = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();
        mtrie.insert("key1".as_bytes(), "aval1".as_bytes(), dummy_extractor);
        mtrie.insert("key2bb".as_bytes(), "aval3".as_bytes(), dummy_extractor);
        let db1 = mtrie.database().clone();

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes(), dummy_extractor);
        mtrie.delete("key2bbb".as_bytes(), |_| vec![]);

        // assert_eq!(db1, mtrie.database()); // FIXME: uncomment?
    }

    #[test]
    fn trie_multiple_prefixed_keys() {
        let key1 = &hex!("af");
        let key2 = &hex!("a2");
        let key3 = &hex!("b3");
        let keyc = &hex!("bf");
        let val = &hex!("bb");
        let mut mtrie = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();
        mtrie.insert(key1, val, dummy_extractor);
        mtrie.insert(key2, val, dummy_extractor);
        mtrie.insert(key3, val, dummy_extractor);
        mtrie.insert(keyc, val, dummy_extractor);
        mtrie.delete(keyc, |_| vec![]);

        assert_eq!(mtrie.get(key1, dummy_extractor).unwrap(), val);
        assert_eq!(mtrie.get(key2, dummy_extractor).unwrap(), val);
        assert_eq!(mtrie.get(key3, dummy_extractor).unwrap(), val);
        assert!(mtrie.get(keyc, dummy_extractor).is_none());
    }
}
