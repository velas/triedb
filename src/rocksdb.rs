//! RocksDB adaptor for TrieDB.

use std::{borrow::Borrow, collections::HashMap};

use primitive_types::H256;
use rocksdb_lib::DB;

use crate::{
    cache::CachedHandle, CachedDatabaseHandle, Change, Database, DatabaseMut, TrieMut, ValueChange,
};

#[derive(Debug, Clone)]
pub struct RocksDatabaseHandle<D>(D);

impl<D> RocksDatabaseHandle<D> {
    pub fn new(db: D) -> Self {
        RocksDatabaseHandle(db)
    }
}

impl<D: Borrow<DB>> CachedDatabaseHandle for RocksDatabaseHandle<D> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.0
            .borrow()
            .get(key.as_ref())
            .expect("Error on reading database")
            .unwrap_or_else(|| panic!("Value for {} not found in database", key))
    }
}

pub type RocksHandle<D> = CachedHandle<RocksDatabaseHandle<D>>;

impl<D: Borrow<DB>> DatabaseMut for RocksHandle<D> {
    fn set(&mut self, key: H256, value: Option<&[u8]>) {
        self.clear_cache();
        let db = self.db.0.borrow();
        if let Some(value) = value {
            db.put(key, value)
                .expect("Unable to put value into database");
        } else {
            db.delete(key).expect("Unable to delete key from database");
        }
    }
}


#[derive(Debug, Clone)]
pub struct RocksMemoryTrieMut<D: Borrow<DB>> {
    root: H256,
    overlay: HashMap<H256, ValueType>,
    handle: RocksHandle<D>,
}

impl<D: Borrow<DB>> RocksMemoryTrieMut<D> {
    fn merge_change(&mut self, change: Change) {
        for change in change.change_list {
            match change {
                ValueChange::Add { key, rlp, .. } => {
                    debug_assert!(self.overlay.insert(key, ValueType::Added(rlp)).is_none());
                }
                ValueChange::Remove { key, .. } => {
                    debug_assert!(self.overlay.remove(&key).is_some());
                }
            }
        }
    }
}

impl<D: Borrow<DB>> Database for RocksMemoryTrieMut<D> {
    fn get(&self, key: H256) -> &[u8] {
        match self.overlay.get(&key) {
            Some(ValueType::Added(data)) => &data,
            Some(ValueType::Removed) => &[],
            None => self.handle.get(key),
        }
    }
}

// TODO: D: Database
impl<D: Borrow<DB>> TrieMut for RocksMemoryTrieMut<D> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.clear_cache();

        let (new_root, change) = crate::insert(self.root, self, key, value);

        self.merge_change(change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        self.clear_cache();

        let (new_root, change) = crate::delete(self.root, self, key);

        self.merge_change(change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        crate::get(self.root, self, key).map(|v| v.into())
    }
}

impl<D: Borrow<DB>> RocksMemoryTrieMut<D> {
    pub fn new(db: D, root: H256) -> Self {
        Self {
            root,
            overlay: Default::default(),
            handle: RocksHandle::new(RocksDatabaseHandle::new(db)),
        }
    }

    pub fn clear_cache(&mut self) {
        self.handle.clear_cache();
    }

    pub fn apply(self) -> Result<H256, String> {
        let db = self.handle.db.0.borrow();

        for (key, value) in self.overlay {
            match value {
                ValueType::Added(value) => db.put(key.as_ref(), &value)?,
                ValueType::Removed => db.delete(key.as_ref())?,
            }
        }
        Ok(self.root)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use tempfile::tempdir;

    use super::*;
    use crate::impls::tests::{Data, K};

    #[quickcheck]
    fn qc_reads_the_same_as_inserts(kvs: HashMap<K, Data>) {
        let dir = tempdir().unwrap();

        let db = DB::open_default(&dir).unwrap();

        let mut triedb = RocksMemoryTrieMut::new(&db, crate::empty_trie_hash());
        for (k, data) in kvs.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }

        // reads before apply
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&TrieMut::get(&triedb, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        // reads after apply
        let root = triedb.apply().unwrap();
        let triedb = RocksMemoryTrieMut::new(&db, root);
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&TrieMut::get(&triedb, &k.to_bytes()).unwrap()).unwrap()
            );
        }
        drop(triedb);
        drop(db);

        // close and re-open database
        let db = DB::open_default(&dir).unwrap();

        let triedb = RocksMemoryTrieMut::new(&db, root);
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&TrieMut::get(&triedb, &k.to_bytes()).unwrap()).unwrap()
            );
        }
    }

    #[quickcheck]
    fn qc_reads_the_same_with_overriden_keys(
        kvs_1: HashMap<K, Data>,
        kvs_2: HashMap<K, Data>,
    ) -> TestResult {
        let keys_1: HashSet<K> = kvs_1.keys().copied().collect();
        let keys_2: HashSet<K> = kvs_2.keys().copied().collect();

        // TODO: save intersection and filter iteration for root_2 and keys_1
        if keys_1.intersection(&keys_2).count() == 0 {
            return TestResult::discard();
        }

        let dir = tempdir().unwrap();

        let db = DB::open_default(&dir).unwrap();

        let mut triedb = RocksMemoryTrieMut::new(&db, crate::empty_trie_hash());
        for (k, data) in kvs_1.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_1 = triedb.apply().unwrap();

        let mut triedb = RocksMemoryTrieMut::new(&db, root_1);
        for (k, data) in kvs_2.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_2 = triedb.apply().unwrap();

        assert_ne!(root_1, root_2);

        let triedb = RocksMemoryTrieMut::new(&db, root_2);
        for (k, data) in kvs_2
            .iter()
            .chain(kvs_1.iter().filter(|(k, _)| !kvs_2.contains_key(k)))
        {
            assert_eq!(
                data,
                &bincode::deserialize::<Data>(&TrieMut::get(&triedb, &k.to_bytes()).unwrap())
                    .unwrap()
            );
        }

        TestResult::passed()
    }
}
