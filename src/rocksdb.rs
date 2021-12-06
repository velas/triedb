//! RocksDB adaptor for TrieDB.

use derivative::Derivative;
use std::borrow::Borrow;

use crate::merkle::MerkleNode;
use log::*;
use primitive_types::H256;
use rlp::Rlp;
use rocksdb_lib::{ColumnFamily, MergeOperands, OptimisticTransactionDB, Transaction};

type DB = OptimisticTransactionDB;

use crate::{
    cache::CachedHandle,
    gc::{DbCounter, ReachableHashes},
    CachedDatabaseHandle, Change, Database, TrieMut,
};

const EXCLUSIVE: bool = true;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct RocksDatabaseHandle<'a, D> {
    db: D,

    #[derivative(Debug = "ignore")]
    counter_cf: Option<&'a ColumnFamily>,
}

impl<'a, D> RocksDatabaseHandle<'a, D> {
    pub fn new(db: D, counter_cf: &'a ColumnFamily) -> Self {
        RocksDatabaseHandle {
            db,
            counter_cf: counter_cf.into(),
        }
    }
    pub fn without_counter(db: D) -> Self {
        RocksDatabaseHandle {
            db,
            counter_cf: None,
        }
    }

    pub fn remove_counter(
        &self,
        b: &mut Transaction<DB>,
        key: H256,
    ) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            b.delete_cf(counter_cf, &key)?
        }
        Ok(())
    }

    pub fn create_counter(
        &self,
        b: &mut Transaction<DB>,
        key: H256,
    ) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            if b.get_for_update_cf(counter_cf, &key, EXCLUSIVE)?.is_none() {
                b.put_cf(counter_cf, &key, &serialize_counter(0))?
            }
        }
        Ok(())
    }

    pub fn increase_atomic(&self, key: H256) -> Result<(), rocksdb_lib::Error>
    where
        D: Borrow<DB>,
    {
        if let Some(counter_cf) = self.counter_cf {
            self.db
                .borrow()
                .merge_cf(counter_cf, &key.as_ref(), &serialize_counter(1))?
        }
        Ok(())
    }
    pub fn decrease_atomic(&self, key: H256) -> Result<(), rocksdb_lib::Error>
    where
        D: Borrow<DB>,
    {
        if let Some(counter_cf) = self.counter_cf {
            self.db
                .borrow()
                .merge_cf(counter_cf, &key.as_ref(), &serialize_counter(-1))?
        }
        Ok(())
    }
    pub fn increase(&self, b: &mut Transaction<DB>, key: H256) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            b.merge_cf(counter_cf, &key.as_ref(), &serialize_counter(1))?
        }
        Ok(())
    }
    pub fn decrease(&self, b: &mut Transaction<DB>, key: H256) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            b.merge_cf(counter_cf, &key.as_ref(), &serialize_counter(-1))?
        }
        Ok(())
    }
    pub fn get_counter_in_tx(
        &self,
        b: &mut Transaction<DB>,
        key: H256,
    ) -> Result<i64, rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            b.get_for_update_cf(counter_cf, key.as_ref(), EXCLUSIVE)
                .map(|s| s.map(|s| deserialize_counter(&s)).unwrap_or_default())
        } else {
            Ok(2) // report two, to make sure that after decrement there still will be atleast one reference
        }
    }
}

pub fn merge_counter(
    key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut val = existing_val.map(deserialize_counter).unwrap_or_default();
    assert_eq!(key.len(), 32);
    for op in operands.iter() {
        let diff = deserialize_counter(op);
        // this assertion is incorrect because rocks can merge multiple values into one.
        // assert!(diff == -1 || diff == 1);
        val += diff;
    }
    Some(serialize_counter(val).to_vec())
}
fn serialize_counter(counter: i64) -> [u8; 8] {
    counter.to_le_bytes()
}

fn deserialize_counter(counter: &[u8]) -> i64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(counter);
    i64::from_le_bytes(bytes)
}

impl<'a, D: Borrow<DB>> CachedDatabaseHandle for RocksDatabaseHandle<'a, D> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.db
            .borrow()
            .get(key.as_ref())
            .expect("Error on reading database")
            .unwrap_or_else(|| panic!("Value for {} not found in database", key))
    }
}

/// Retry is used because optimistic transactions can fail if other thread change some value.
macro_rules! retry {
    {$($tokens:tt)*} => {
        let mut retry = move || -> Result<_, anyhow::Error> {
            let result = { $($tokens)* };
            Ok(result)
        };
        const NUM_RETRY: usize = 3;
        let mut e = None; //use option because rust think that this variable can be uninit
        for _ in 0..NUM_RETRY {
            e = Some(retry());
            match e.as_ref().unwrap() {
                Ok(_) => break,
                Err(e) => log::warn!("Error during transaction execution {}", e)

            }
        }
        e.unwrap()
         .expect(&format!("Failed to retry operation for {} times", NUM_RETRY))

    };
}
pub type RocksHandle<'a, D> = CachedHandle<RocksDatabaseHandle<'a, D>>;

impl<'a, D: Borrow<DB>> DbCounter for RocksHandle<'a, D> {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], mut child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            // let mut write_batch = WriteBatch::default();
            if tx
                .get_for_update(key.as_ref(), EXCLUSIVE)
                .map_err(|e| anyhow::format_err!("Cannot get key {}", e))?
                .is_none()
            {
                let rlp = Rlp::new(&value);
                let node = MerkleNode::decode(&rlp)?;
                trace!("inserting node {}=>{:?}", key, node);
                for hash in ReachableHashes::collect(&node, &mut child_extractor).childs() {
                    self.db.increase(&mut tx, hash)?;
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
        retry! {
            let mut nodes = vec![];
            //TODO: retry
            if let Some(value) = db.get(key.as_ref())? {
                let mut tx = db.transaction();
                let count = self.db.get_counter_in_tx(&mut tx, key)?;
                if count > 0 {
                    return Ok(vec![]);
                }
                tx.delete(&key.as_ref())?;
                self.db.remove_counter(&mut tx, key)?;

                let rlp = Rlp::new(&value);
                let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                for hash in ReachableHashes::collect(&node, &mut child_extractor).childs() {
                    let child_count = self.db.get_counter_in_tx(&mut tx, hash)?;
                    if child_count <= 1 {
                        nodes.push(hash);
                    }
                    self.db.decrease(&mut tx, hash)?;
                }

                tx.commit()?;
            }
            nodes
        }
    }

    fn gc_pin_root(&self, key: H256) {
        let db = self.db.db.borrow();
        let mut tx = db.transaction();
        self.db.increase(&mut tx, key).expect("cannot write batch");
        tx.commit().expect("cannot write batch");
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        let db = self.db.db.borrow();
        let mut tx = db.transaction();
        self.db.decrease(&mut tx, key).expect("cannot write batch");
        tx.commit().expect("cannot write batch");
        self.gc_count(key) == 0
    }
}

#[derive(Debug)]
pub struct RocksMemoryTrieMut<'a, D: Borrow<DB>> {
    root: H256,
    change: Change,
    handle: RocksHandle<'a, D>,
}

impl<'a, D: Borrow<DB>> Database for RocksMemoryTrieMut<'a, D> {
    fn get(&self, key: H256) -> &[u8] {
        if self.change.adds.contains_key(&key) {
            self.change.adds.get(&key).unwrap()
        } else {
            self.handle.get(key)
        }
    }
}

// TODO: D: Database
impl<'a, D: Borrow<DB>> TrieMut for RocksMemoryTrieMut<'a, D> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.clear_cache();

        let (new_root, change) = crate::insert(self.root, self, key, value);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        self.clear_cache();

        let (new_root, change) = crate::delete(self.root, self, key);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        crate::get(self.root, self, key).map(|v| v.into())
    }
}

impl<'a, D: Borrow<DB>> RocksMemoryTrieMut<'a, D> {
    pub fn new(db: D, root: H256, counter_cf: &'a ColumnFamily) -> Self {
        Self {
            root,
            change: Change::default(),
            handle: RocksHandle::new(RocksDatabaseHandle::new(db, counter_cf)),
        }
    }

    pub fn without_counter(db: D, root: H256) -> Self {
        Self {
            root,
            change: Change::default(),
            handle: RocksHandle::new(RocksDatabaseHandle::without_counter(db)),
        }
    }

    pub fn clear_cache(&mut self) {
        self.handle.clear_cache();
    }

    /// Apply changes to database
    /// Explicitly ask for setting ignore_gc flag.
    /// This will make sure
    pub fn apply(self, ignore_gc: bool) -> Result<H256, String> {
        if ignore_gc == self.handle.db.counter_cf.is_some() {
            return Err(String::from(
                "Gc settings for apply function differ from RocksdbHandle creation",
            ));
        }

        let db = self.handle.db.db.borrow();

        for key in self.change.removes {
            db.delete(key.as_ref())?;
        }

        for (key, value) in self.change.adds {
            db.put(key.as_ref(), &value)?;
        }

        Ok(self.root)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use crate::empty_trie_hash;
    use crate::gc::TrieCollection;
    use crate::merkle::MerkleNode;
    use hex_literal::hex;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rlp::Rlp;
    use rocksdb_lib::{ColumnFamilyDescriptor, Options};
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    use super::*;
    use crate::gc::tests::{FixedData, Key, RootGuard};
    use crate::impls::tests::{Data, K};

    fn no_childs(_: &[u8]) -> Vec<H256> {
        vec![]
    }

    fn default_opts() -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts
    }

    fn counter_cf_opts() -> Options {
        let mut opts = default_opts();
        opts.set_merge_operator_associative("inc_counter", merge_counter);
        opts
    }
    #[quickcheck]
    fn qc_reads_the_same_as_inserts(kvs: HashMap<K, Data>) {
        let dir = tempdir().unwrap();

        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();
        let mut triedb = RocksMemoryTrieMut::without_counter(&db, crate::empty_trie_hash());
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
        let root = triedb.apply(true).unwrap();
        let triedb = RocksMemoryTrieMut::new(&db, root, cf);
        for k in kvs.keys() {
            assert_eq!(
                kvs[k],
                bincode::deserialize(&TrieMut::get(&triedb, &k.to_bytes()).unwrap()).unwrap()
            );
        }
        drop(triedb);
        drop(cf);

        drop(db);

        // close and re-open database
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let triedb = RocksMemoryTrieMut::new(&db, root, cf);
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
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let mut triedb = RocksMemoryTrieMut::new(&db, crate::empty_trie_hash(), cf);
        for (k, data) in kvs_1.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_1 = triedb.apply(false).unwrap();

        let mut triedb = RocksMemoryTrieMut::new(&db, root_1, cf);
        for (k, data) in kvs_2.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_2 = triedb.apply(false).unwrap();

        assert_ne!(root_1, root_2);

        // can read data from bd without counting references
        let triedb = RocksMemoryTrieMut::without_counter(&db, root_2);
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

    #[test]
    fn it_counts_childs_as_expected_and_cleanup_correctly() {
        let key1 = &hex!("bbaa");
        let key2 = &hex!("ffaa");
        let key3 = &hex!("bbcc");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";
        let value3 = b"other data_______________________";
        let value3_1 = b"changed data_____________________";
        let value2_1 = b"changed data_____________________";

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandle::new(&db, cf)));

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        trie.insert(key3, value3);
        let patch = trie.into_patch();
        assert_eq!(collection.database.gc_count(patch.root), 0);
        let root = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database.gc_count(root), 0);

        // mark root for pass GC
        collection.database.gc_pin_root(root);
        assert_eq!(collection.database.gc_count(root), 1);

        // CHECK CHILDS counts
        println!("root={}", root);
        let node = collection.database.get(root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(childs.len(), 2); // "bb..", "ffaa", check test doc comments

        for child in &childs {
            assert_eq!(collection.database.gc_count(*child), 1);
        }

        let mut trie = collection.trie_for(root);
        assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
        assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
        assert_eq!(TrieMut::get(&trie, key3), Some(value3.to_vec()));

        trie.insert(key3, value3_1);
        assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));
        let patch = trie.into_patch();

        assert_eq!(collection.database.gc_count(patch.root), 0);
        let another_root = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database.gc_count(another_root), 0);

        // mark root for pass GC
        collection.database.gc_pin_root(another_root);
        assert_eq!(collection.database.gc_count(another_root), 1);

        let node = collection.database.get(another_root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let another_root_childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(another_root_childs.len(), 2); // "bb..", "ffaa", check test doc comments

        let first_set: BTreeSet<_> = childs.into_iter().collect();
        let another_set: BTreeSet<_> = another_root_childs.into_iter().collect();

        let diff_child: Vec<_> = another_set.intersection(&first_set).collect();
        assert_eq!(diff_child.len(), 1);

        assert_eq!(collection.database.gc_count(*diff_child[0]), 2);

        for child in first_set.symmetric_difference(&another_set) {
            assert_eq!(collection.database.gc_count(*child), 1);
        }

        // Adding one dublicate

        let mut trie = collection.trie_for(another_root);

        // adding dublicate value should not affect RC
        trie.insert(key1, value1);

        let patch = trie.into_patch();
        assert_eq!(patch.root, another_root);

        // adding one more changed element, and make additional conflict.

        let mut trie = collection.trie_for(another_root);

        trie.insert(key2, value2_1);

        let patch = trie.into_patch();

        let latest_root = collection.apply_increase(patch, no_childs);

        collection.database.gc_pin_root(latest_root);

        let node = collection.database.get(latest_root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let latest_root_childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(latest_root_childs.len(), 2); // "bb..", "ffaa", check test doc comments

        let latest_set: BTreeSet<_> = latest_root_childs.into_iter().collect();
        assert_eq!(latest_set.intersection(&first_set).count(), 0);

        // check only newest childs

        let diffs: Vec<_> = latest_set.difference(&another_set).collect();

        assert_eq!(diffs.len(), 1);
        for child in &diffs {
            assert_eq!(collection.database.gc_count(**child), 1);
        }

        let intersections: Vec<_> = latest_set.intersection(&another_set).collect();

        assert_eq!(intersections.len(), 1);
        for child in &intersections {
            assert_eq!(collection.database.gc_count(**child), 2);
        }

        // TRY cleanup first root.

        assert!(collection.database.gc_unpin_root(root));

        let mut elems = collection.database.gc_cleanup_layer(&[root], no_childs);
        assert_eq!(elems.len(), 1);
        while !elems.is_empty() {
            // perform additional check, that all removed elements should be also removed from db.
            let cloned_elems = elems.clone();
            elems = collection.database.gc_cleanup_layer(&elems, no_childs);
            for child in cloned_elems {
                assert!(collection.database.db.db.get(&child).unwrap().is_none());
            }
        }

        // this should not affect latest roots elements
        let sym_diffs: Vec<_> = latest_set.symmetric_difference(&another_set).collect();
        assert_eq!(sym_diffs.len(), 2);
        for child in &sym_diffs {
            assert_eq!(collection.database.gc_count(**child), 1);
        }

        assert_eq!(intersections.len(), 1);
        for child in &intersections {
            assert_eq!(collection.database.gc_count(**child), 2);
        }
        // but affect first root diffs
        assert_eq!(collection.database.gc_count(*diff_child[0]), 1);

        // and also remove all nodes from first root
        let first_root_keys: Vec<_> = first_set.difference(&another_set).collect();
        assert_eq!(first_root_keys.len(), 1);
        for child in first_root_keys {
            assert_eq!(collection.database.gc_count(*child), 0);

            assert!(collection.database.db.db.get(child).unwrap().is_none());
        }
    }

    #[quickcheck]
    fn qc_handles_several_key_changes(
        kvs_1: HashMap<Key, FixedData>,
        kvs_2: HashMap<Key, FixedData>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandle::new(&db, cf)));

        let mut root = crate::empty_trie_hash();
        let mut roots = Vec::new();

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.0, &data.0);

            let patch = trie.into_patch();
            root = collection.apply_increase(patch, no_childs);

            roots.push(RootGuard::new(&collection.database, root, no_childs));
        }

        let last_root_guard = roots.pop().unwrap();

        // perform cleanup of all intermediate roots
        for stale_root in roots {
            drop(stale_root);
        }

        // expect for kvs to be available
        let trie = collection.trie_for(root);
        for k in kvs_1.keys() {
            assert_eq!(&kvs_1[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        let mut roots = Vec::new();

        for (k, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.0, &data.0);
            let patch = trie.into_patch();
            root = collection.apply_increase(patch, no_childs);
            roots.push(RootGuard::new(&collection.database, root, no_childs));
        }

        let second_collection_root_guard = roots.pop().unwrap();
        // perform cleanup of all intermediate roots
        drop(roots);

        let trie = collection.trie_for(last_root_guard.root);
        for k in kvs_1.keys() {
            assert_eq!(&kvs_1[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        let trie = collection.trie_for(second_collection_root_guard.root);
        for k in kvs_2.keys() {
            assert_eq!(&kvs_2[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        drop(last_root_guard);
        drop(second_collection_root_guard);

        use rocksdb_lib::IteratorMode;
        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        println!("Debug cf");
        for (k, v) in db.iterator_cf(cf, IteratorMode::Start) {
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);

        TestResult::passed()
    }

    #[derive(Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct DataWithRoot {
        pub root: H256,
    }

    impl DataWithRoot {
        fn get_childs(data: &[u8]) -> Vec<H256> {
            bincode::deserialize::<Self>(data)
                .ok()
                .into_iter()
                .map(|e| e.root)
                .collect()
        }
    }
    impl Default for DataWithRoot {
        fn default() -> Self {
            Self {
                root: empty_trie_hash!(),
            }
        }
    }

    // todo implement data with child collection.
    #[quickcheck]
    fn qc_handles_inner_roots(
        alice_key: Key,
        alice_chages: Vec<(Key, FixedData)>,
        bob_key: Key,
        bob_storage: HashMap<Key, FixedData>,
    ) -> TestResult {
        if alice_chages.is_empty() || bob_storage.is_empty() {
            return TestResult::discard();
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandle::new(&db, cf)));

        let mut top_level_root = RootGuard::new(
            &collection.database,
            crate::empty_trie_hash(),
            DataWithRoot::get_childs,
        );

        let mut alice_storage_mem = HashMap::new();
        {
            for (k, data) in alice_chages.iter() {
                alice_storage_mem.insert(*k, *data);

                let mut account_trie = collection.trie_for(top_level_root.root);

                let mut alice_account: DataWithRoot = TrieMut::get(&account_trie, &alice_key.0)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();

                let mut storage_trie = collection.trie_for(alice_account.root);
                storage_trie.insert(&k.0, &data.0);

                let storage_patch = storage_trie.into_patch();

                alice_account.root = storage_patch.root;

                account_trie.insert(&alice_key.0, &bincode::serialize(&alice_account).unwrap());

                let mut account_patch = account_trie.into_patch();

                account_patch.change.merge(&storage_patch.change);
                top_level_root = RootGuard::new(
                    &collection.database,
                    collection.apply_increase(account_patch, DataWithRoot::get_childs),
                    DataWithRoot::get_childs,
                );
            }
        };

        {
            for (k, data) in bob_storage.iter() {
                let mut account_trie = collection.trie_for(top_level_root.root);

                let mut bob_account: DataWithRoot = TrieMut::get(&account_trie, &bob_key.0)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();

                let mut storage_trie = collection.trie_for(bob_account.root);
                storage_trie.insert(&k.0, &data.0);

                let storage_patch = storage_trie.into_patch();

                bob_account.root = storage_patch.root;

                account_trie.insert(&bob_key.0, &bincode::serialize(&bob_account).unwrap());

                let mut account_patch = account_trie.into_patch();

                account_patch.change.merge(&storage_patch.change);
                top_level_root = RootGuard::new(
                    &collection.database,
                    collection.apply_increase(account_patch, DataWithRoot::get_childs),
                    DataWithRoot::get_childs,
                );
            }
        };

        let accounts_storage = collection.trie_for(top_level_root.root);
        let alice_account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &alice_key.0).unwrap()).unwrap();
        let bob_account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &bob_key.0).unwrap()).unwrap();

        let alice_storage_trie = collection.trie_for(alice_account.root);
        for k in alice_storage_mem.keys() {
            assert_eq!(
                &alice_storage_mem[k].0[..],
                &TrieMut::get(&alice_storage_trie, &k.0).unwrap()
            );
        }

        let bob_storage_trie = collection.trie_for(bob_account.root);
        for k in bob_storage.keys() {
            assert_eq!(
                &bob_storage[k].0[..],
                &TrieMut::get(&bob_storage_trie, &k.0).unwrap()
            );
        }

        // check cleanup db
        drop(top_level_root);

        use rocksdb_lib::IteratorMode;
        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        println!("Debug cf");
        for (k, v) in db.iterator_cf(cf, IteratorMode::Start) {
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);

        TestResult::passed()
    }

    #[quickcheck]
    fn qc_handles_several_roots_via_gc(
        kvs_1: HashMap<K, Data>,
        kvs_2: HashMap<K, Data>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }
        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandle::new(&db, cf)));

        let mut root = crate::empty_trie_hash();
        let mut root_guards = vec![];

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());

            let patch = trie.into_patch();
            root = collection.apply_increase(patch, no_childs);

            root_guards.push(RootGuard::new(&collection.database, root, no_childs));
        }

        let mut root_guard = root_guards.pop().unwrap();

        drop(root_guards);
        // expect for kvs to be available
        let trie = collection.trie_for(root);
        for k in kvs_1.keys() {
            assert_eq!(
                kvs_1[k],
                bincode::deserialize(&TrieMut::get(&trie, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        for (k, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &&bincode::serialize(data).unwrap());
            let patch = trie.into_patch();
            root = collection.apply_increase(patch, no_childs);
            root_guard = RootGuard::new(&collection.database, root, no_childs);
        }

        let trie = collection.trie_for(root);
        for k in kvs_2.keys() {
            assert_eq!(
                kvs_2[k],
                bincode::deserialize(&TrieMut::get(&trie, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        drop(root_guard);

        use rocksdb_lib::IteratorMode;
        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        println!("Debug cf");
        for (k, v) in db.iterator_cf(cf, IteratorMode::Start) {
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);

        TestResult::passed()
    }
}
