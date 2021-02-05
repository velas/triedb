//! RocksDB adaptor for TrieDB.

use primitive_types::H256;
use rocksdb_lib::DB;

use crate::{delete, get, insert, CachedDatabaseHandle, CachedHandle, Change, Database, TrieMut};

pub struct RocksDatabaseHandle<'a>(&'a DB);

impl<'a> CachedDatabaseHandle for RocksDatabaseHandle<'a> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.0
            .get(key.as_ref())
            .expect("Error on reading database")
            .expect("Value not found in database")
    }
}

impl<'a> RocksDatabaseHandle<'a> {
    pub fn new(db: &'a DB) -> Self {
        RocksDatabaseHandle(db)
    }
}

pub type RocksHandle<'a> = CachedHandle<RocksDatabaseHandle<'a>>;

pub struct RocksMemoryTrieMut<'a> {
    handle: RocksHandle<'a>,
    change: Change,
    root: H256,
    db: &'a DB,
    cached: bool,
}

impl<'a, 'b> Database for &'b RocksMemoryTrieMut<'a> {
    fn get(&self, key: H256) -> &[u8] {
        if self.change.adds.contains_key(&key) {
            self.change.adds.get(&key).unwrap()
        } else {
            self.handle.get(key)
        }
    }
}

impl<'a> TrieMut for RocksMemoryTrieMut<'a> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.clear_cache();

        let (new_root, change) = insert(self.root, &&*self, key, value);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        self.clear_cache();

        let (new_root, change) = delete(self.root, &&*self, key);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &self, key).map(|v| v.into())
    }
}

impl<'a> RocksMemoryTrieMut<'a> {
    fn clear_cache(&mut self) {
        if !self.cached {
            self.handle = RocksHandle::new(RocksDatabaseHandle::new(self.db));
        }
    }

    pub fn new(db: &'a DB, root: H256, cached: bool) -> Self {
        Self {
            handle: RocksHandle::new(RocksDatabaseHandle::new(db)),
            change: Change::default(),
            root,
            db,
            cached,
        }
    }

    pub fn new_cached(db: &'a DB, root: H256) -> Self {
        Self::new(db, root, true)
    }

    pub fn new_uncached(db: &'a DB, root: H256) -> Self {
        Self::new(db, root, false)
    }

    pub fn apply(self) -> Result<H256, String> {
        for (key, value) in self.change.adds {
            self.db.put(key.as_ref(), &value)?;
        }

        for key in self.change.removes {
            self.db.delete(key.as_ref())?;
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

        let mut triedb = RocksMemoryTrieMut::new_uncached(&db, crate::empty_trie_hash());
        for (k, data) in kvs.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }

        // reads before apply
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&triedb.get(&k.to_bytes()).unwrap()).unwrap()
            );
        }

        // reads after apply
        let root = triedb.apply().unwrap();
        let triedb = RocksMemoryTrieMut::new_uncached(&db, root);
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&triedb.get(&k.to_bytes()).unwrap()).unwrap()
            );
        }
        drop(triedb);
        drop(db);

        // close and re-open database
        let db = DB::open_default(&dir).unwrap();

        let triedb = RocksMemoryTrieMut::new_uncached(&db, root);
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&triedb.get(&k.to_bytes()).unwrap()).unwrap()
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

        let mut triedb = RocksMemoryTrieMut::new_uncached(&db, crate::empty_trie_hash());
        for (k, data) in kvs_1.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_1 = triedb.apply().unwrap();

        let mut triedb = RocksMemoryTrieMut::new_uncached(&db, root_1);
        for (k, data) in kvs_2.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_2 = triedb.apply().unwrap();

        assert_ne!(root_1, root_2);

        let triedb = RocksMemoryTrieMut::new_uncached(&db, root_2);
        for (k, data) in kvs_2
            .iter()
            .chain(kvs_1.iter().filter(|(k, _)| !kvs_2.contains_key(k)))
        {
            assert_eq!(
                data,
                &bincode::deserialize::<Data>(&triedb.get(&k.to_bytes()).unwrap()).unwrap()
            );
        }

        TestResult::passed()
    }
}
