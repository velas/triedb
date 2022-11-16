use primitive_types::H256;

use crate::{gc::DbCounter, Database, empty_trie_hash};

pub struct RootGuard<'a, D: Database + DbCounter, F: FnMut(&[u8]) -> Vec<H256>> {
    pub root: H256,
    db: &'a D,
    child_collector: F,
}
impl<'a, D: Database + DbCounter, F: FnMut(&[u8]) -> Vec<H256>> RootGuard<'a, D, F> {
    pub fn new(db: &'a D, root: H256, child_collector: F) -> Self {
        if root != empty_trie_hash!() {
            db.gc_pin_root(root);
        }
        Self {
            root,
            db,
            child_collector,
        }
    }
    // Return true if root is valid node
    pub fn check_root_exist(&self) -> bool {
        if self.root == empty_trie_hash!() {
            return true;
        }

        self.db.node_exist(self.root)
    }
    // Release root reference, but skip cleanup.
    pub fn leak_root(mut self) -> H256 {
        let root = self.root;
        self.db.gc_unpin_root(root);
        self.root = empty_trie_hash!();
        root
    }
}

impl<'a, D: Database + DbCounter, F: FnMut(&[u8]) -> Vec<H256>> Drop for RootGuard<'a, D, F> {
    fn drop(&mut self) {
        if self.root == empty_trie_hash!() {
            return;
        }
        if self.db.gc_unpin_root(self.root) {
            let mut elems = self
                .db
                .gc_cleanup_layer(&[self.root], &mut self.child_collector);

            while !elems.is_empty() {
                elems = self.db.gc_cleanup_layer(&elems, &mut self.child_collector);
            }
        }
    }
}
