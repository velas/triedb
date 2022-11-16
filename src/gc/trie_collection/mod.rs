use primitive_types::H256;


use crate::{Database, empty_trie_hash};

use super::DbCounter;

mod trie_mut;
mod root_guard;

use trie_mut::DatabaseTrieMutPatch;
pub use trie_mut::DatabaseTrieMut;
pub use root_guard::RootGuard;



pub struct TrieCollection<D> {
    pub database: D,
}

impl<D: DbCounter + Database> TrieCollection<D> {
    pub fn new(database: D) -> Self {
        Self { database }
    }

    pub fn trie_for(&self, root: H256) -> DatabaseTrieMut<&D> {
        DatabaseTrieMut::trie_for(&self.database, root)
    }

    // returns guard to empty trie;
    pub fn empty_guard<F: FnMut(&[u8]) -> Vec<H256>>(&self, child_extractor: F) -> RootGuard<D, F> {
        RootGuard::new(&self.database, empty_trie_hash!(), child_extractor)
    }

    // Apply changes and only increase child counters
    pub fn apply_increase<F>(
        &self,
        DatabaseTrieMutPatch { root, change }: DatabaseTrieMutPatch,
        mut child_extractor: F,
    ) -> RootGuard<D, F>
    where
        F: FnMut(&[u8]) -> Vec<H256> + Clone,
    {
        let root_guard = RootGuard::new(&self.database, root, child_extractor.clone());

        // we collect changs from bottom to top, but insert should be done from root to child.
        for (key, value) in change.changes.into_iter().rev() {
            if let Some(value) = value {
                self.database
                    .gc_insert_node(key, &value, &mut child_extractor);
            }
        }

        root_guard
    }
}
