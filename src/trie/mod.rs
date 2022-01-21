use std::collections::HashMap;

use super::H256;
use crate::database::{Database, DatabaseMut};
use crate::empty_trie_hash;

pub mod typed;

pub struct TrieHandle<D> {
    database: D,
    root: H256,
}

impl<D: Default> Default for TrieHandle<D> {
    fn default() -> Self {
        Self {
            database: Default::default(),
            root: empty_trie_hash!(),
        }
    }
}

impl<D> TrieHandle<D> {
    pub fn new(database: D, root: H256) -> Self {
        Self { database, root }
    }

    pub fn root(&self) -> H256 {
        self.root
    }
    pub fn inner(&self) -> &D {
        &self.database
    }
}
impl<D: DatabaseMut> TrieHandle<D> {
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = crate::insert(self.root, &self.database, key, value);

        self.database.apply_change(change);
        self.root = new_root;
    }

    pub fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = crate::delete(self.root, &self.database, key);

        self.database.apply_change(change);
        self.root = new_root;
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        crate::get(self.root, &self.database, key).map(|v| v.into())
    }

    pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> Self
    where
        Self: Default,
    {
        let (new_root, change) = crate::build(map);

        let mut ret = Self::default();
        ret.database.apply_change(change);
        ret.root = new_root;

        ret
    }
}
