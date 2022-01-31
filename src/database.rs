use std::sync::Arc;

use primitive_types::H256;

/// An immutable database handle.
pub trait Database {
    /// Get a raw value from the database.
    fn get(&self, key: H256) -> &[u8];
}

impl<'a, T: Database> Database for &'a T {
    fn get(&self, key: H256) -> &[u8] {
        T::get(*self, key)
    }
}

impl<T: Database> Database for Arc<T> {
    fn get(&self, key: H256) -> &[u8] {
        T::get(self.as_ref(), key)
    }
}

pub trait DatabaseMut {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>;

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node<F>(&self, key: H256, child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>;

    // increase root link count
    fn gc_pin_root(&self, root: H256);

    // return true if root can be cleanedup.
    fn gc_unpin_root(&self, root: H256) -> bool;

    // Introspection only:
    // Return count of references to key.
    // Should not be used in underlying modification,
    // To modify counter use gc_insert_node/gc_try_cleanup_node.
    fn gc_count(&self, key: H256) -> usize;

    // Return true if node data is exist, and it counter more than 0;
    fn node_exist(&self, key: H256) -> bool;

    // Any of remove is a link to MerkleNode.
    // Every remove should be processed atomicly:
    // 1. checks if removes counter == 0.
    // 2. if it == 0 remove from database, and decrement child counters.
    // 3. return list of childs with counter == 0
    fn gc_cleanup_layer<F>(&self, removes: &[H256], mut child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        let mut result = Vec::new();
        for remove in removes {
            result.extend_from_slice(&self.gc_try_cleanup_node(*remove, &mut child_extractor))
        }
        result
    }
}
