use log::*;
use rlp::Rlp;
use std::borrow::Borrow;
use primitive_types::H256;

use crate::gc::DbCounter;
use crate::gc::reachable_hashes::ReachableHashes;
use crate::merkle::MerkleNode;

use super::{DB, RocksHandle, EXCLUSIVE};

impl<'a, D: Borrow<DB>> DbCounter for RocksHandle<'a, D> {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], mut child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        let rlp = Rlp::new(&value);
        let node = MerkleNode::decode(&rlp).expect("Data should be decodable node");
        let childs = ReachableHashes::collect(&node, &mut child_extractor).childs();
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            // let mut write_batch = WriteBatch::default();
            if tx
                .get_for_update(key.as_ref(), EXCLUSIVE)
                .map_err(|e| anyhow::format_err!("Cannot get key {}", e))?
                .is_none()
            {
                trace!("inserting node {}=>{:?}", key, node);
                for hash in &childs {
                    self.db.increase(&mut tx, *hash)?;
                }

                tx.put(key.as_ref(), value)?;
                self.db.create_counter(&mut tx, key)?;
                tx.commit()?;
            }
        }
    }
    fn gc_count(&self, key: H256) -> usize {
        let db = self.db.db.borrow();
        let mut tx = db.transaction();
        self.db
            .get_counter_in_tx(&mut tx, key)
            .expect("Cannot read value") as usize
    }

    // Return true if node data is exist, and it counter more than 0;
    fn node_exist(&self, key: H256) -> bool {
        self.db
            .db
            .borrow()
            .get(key.as_ref())
            .unwrap_or_default()
            .is_some()
            && self.gc_count(key) > 0
    }

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node<F>(&self, key: H256, mut child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        let db = self.db.db.borrow();
        if self.db.counter_cf.is_none() {
            return vec![];
        };

        // To make second retry execute faster, cache child keys.
        let mut cached_childs = None;
        trace!("try removing node {}", key);
        retry! {
            let mut nodes = Vec::with_capacity(16);
            //TODO: retry

            let mut tx = db.transaction();
            if let Some(value) = tx.get_for_update(key.as_ref(), EXCLUSIVE)? {
                let count = self.db.get_counter_in_tx(&mut tx, key)?;
                if count > 0 {
                    trace!("ignore removing node {}, counter: {}", key, count);
                    return Ok(vec![]);
                }
                tx.delete(&key.as_ref())?;
                self.db.remove_counter(&mut tx, key)?;


                let childs = cached_childs.take().unwrap_or_else(||{
                    let rlp = Rlp::new(&value);
                    let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                    ReachableHashes::collect(&node, &mut child_extractor).childs()
                });

                for hash in &childs {
                    let child_count = self.db.decrease(&mut tx, *hash)?;
                    if child_count <= 0 {
                        nodes.push(*hash);
                    }
                }

                cached_childs = Some(childs);

                tx.commit()?;
            }
            nodes
        }
    }

    fn gc_pin_root(&self, key: H256) {
        trace!("Pin root:{}", key);
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            self.db.increase(&mut tx, key)?;
            tx.commit()?;
        }
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        trace!("Unpin root:{}", key);
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            self.db.decrease(&mut tx, key)?;
            tx.commit()?;
            self.gc_count(key) == 0
        }
    }
}
