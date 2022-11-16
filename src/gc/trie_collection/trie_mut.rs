use std::borrow::Borrow;
use std::collections::HashMap;

use primitive_types::H256;

use crate::{Change, Database, TrieMut};
use crate::{insert, delete, get};


pub struct DatabaseTrieMut<D> {
    database: D,
    change: Change,
    // latest state of changed data.
    change_data: HashMap<H256, Vec<u8>>,
    root: H256,
}

#[derive(Default)]
pub struct DatabaseTrieMutPatch {
    pub root: H256,
    pub change: Change,
}
// TODO: impl DatabaseMut for DatabaseTrieMut and lookup changes before database

impl<D: Database> DatabaseTrieMut<D> {
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

impl<D: Database> Database for DatabaseTrieMut<D> {
    fn get(&self, key: H256) -> &[u8] {
        if let Some(bytes) = self.change_data.get(&key) {
            &**bytes
        } else {
            self.database.borrow().get(key)
        }
    }
}

impl<D: Database> TrieMut for DatabaseTrieMut<D> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, self, key, value);

        self.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, self, key);

        self.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, self, key).map(|v| v.into())
    }
}
