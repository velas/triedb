#![allow(dead_code)] // FIXME: delete this lint
use std::collections::HashMap;

use super::H256;
use crate::database::{Database, DatabaseMut};
use crate::empty_trie_hash;
use crate::Change;

pub mod typed;

#[derive(Default)]
pub struct DatabaseTrieMutPatch {
    pub root: H256,
    pub change: Change,
}

pub struct TrieHandle<D> {
    database: D,
    root: H256,
    change: Change,
    change_data: HashMap<H256, Vec<u8>>,
}

impl<D: Default> Default for TrieHandle<D> {
    fn default() -> Self {
        Self {
            database: Default::default(),
            root: empty_trie_hash!(),
            change: Change::default(),
            change_data: HashMap::default()
        }
    }
}

impl<D> TrieHandle<D> {
    pub fn new(database: D, root: H256) -> Self {
        let change = Change::default();
        let change_data = HashMap::default();
        Self { database, root, change, change_data }
    }

    pub fn root(&self) -> H256 {
        self.root
    }
    pub fn inner(&self) -> &D {
        &self.database
    }
}
impl<D: Database + DatabaseMut> TrieHandle<D> {
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = crate::insert(self.root, &self.database, key, value);

        self.merge(&change);
        self.root = new_root;
    }

    pub fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = crate::delete(self.root, &self.database, key);

        self.merge(&change);
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
        ret.merge(&change);
        ret.root = new_root;

        ret
    }

    pub fn merge(&mut self, change: &Change) {
        for (key, v) in &change.changes {
            if let Some(v) = v {
                self.change_data.insert(*key, v.clone());
            } else {
                self.change_data.remove(key);
            }
        }
        self.change.merge(change)
    }

    pub fn into_patch(self) -> DatabaseTrieMutPatch {
        let Self {
            root,
            change,
            change_data,
            ..
        } = self;
        // ideally we need map ordered by push time, but currently we use log+map so we need
        // filter changes that was removed during latest insert, collect only changes that is equal to actual.
        let changes = change
            .changes
            .into_iter()
            .filter(|(k, v)| v.is_some() == change_data.get(k).is_some())
            .collect();
        DatabaseTrieMutPatch {
            root,
            change: Change { changes },
        }
    }

    pub fn trie_for(db: D, root: H256) -> Self {
        Self {
            database: db,
            change: Change::default(),
            change_data: Default::default(),
            root,
        }
    }
}
