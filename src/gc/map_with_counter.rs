//use asterix to avoid unresolved import https://github.com/rust-analyzer/rust-analyzer/issues/7459#issuecomment-907714513
use std::sync::Arc;
use dashmap::{mapref::entry::Entry, DashMap};
use log::*;

use rlp::Rlp;
use primitive_types::H256;
use crate::MerkleNode;

use crate::{
    cache::CachedHandle, CachedDatabaseHandle, 
};
use super::DbCounter;
use super::reachable_hashes::ReachableHashes;

#[derive(Default)]
pub struct MapWithCounter {
    pub(super) counter: DashMap<H256, usize>,
    pub(super) data: DashMap<H256, Vec<u8>>,
}
impl MapWithCounter {
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

impl CachedDatabaseHandle for Arc<MapWithCounter> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.data
            .get(&key)
            .unwrap_or_else(|| panic!("Value for {} not found in database", key))
            .clone()
    }
}

pub type MapWithCounterCached = CachedHandle<Arc<MapWithCounter>>;

impl DbCounter for MapWithCounterCached {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        match self.db.data.entry(key) {
            Entry::Occupied(_) => {}
            Entry::Vacant(v) => {
                let rlp = Rlp::new(&value);
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
            Entry::Occupied(entry) => {
                // in this code we lock data, so it's okay to check counter from separate function
                if self.gc_count(key) == 0 {
                    let value = entry.remove();
                    let rlp = Rlp::new(&value);
                    let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                    return ReachableHashes::collect(&node, child_extractor)
                        .childs()
                        .into_iter()
                        .filter(|k| self.db.decrease(*k) == 0)
                        .collect();
                }
            }
            Entry::Vacant(_) => {}
        };
        vec![]
    }

    fn gc_pin_root(&self, key: H256) {
        self.db.increase(key);
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        self.db.decrease(key) == 0
    }
}

