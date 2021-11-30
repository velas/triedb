//! RocksDB adaptor for TrieDB.

use derivative::Derivative;
use std::borrow::Borrow;

use crate::merkle::MerkleNode;
use log::*;
use primitive_types::H256;
use rlp::Rlp;
use rocksdb_lib::{ColumnFamily, MergeOperands, WriteBatch, DB};

use crate::{cache::CachedHandle, gc::DbCounter, CachedDatabaseHandle, Change, Database, TrieMut};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct RocksDatabaseHandle<'a, D> {
    db: D,

    #[derivative(Debug = "ignore")]
    counter_cf: &'a ColumnFamily,
}

impl<'a, D> RocksDatabaseHandle<'a, D> {
    pub fn new(db: D, counter_cf: &'a ColumnFamily) -> Self {
        RocksDatabaseHandle { db, counter_cf }
    }

    // mark counter as zero, to make write batch conflict
    pub fn remove_counter(&self, b: &mut WriteBatch, key: H256) {
        b.put_cf(&self.counter_cf, key, serialize_counter(0))
    }
    pub fn increase(&self, b: &mut WriteBatch, key: H256) {
        b.merge_cf(&self.counter_cf, key, serialize_counter(1))
    }
    pub fn decrease(&self, b: &mut WriteBatch, key: H256) {
        b.merge_cf(&self.counter_cf, key, serialize_counter(-1))
    }
}

pub fn merge_counter(
    key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &mut MergeOperands,
) -> Option<Vec<u8>> {
    let mut val = existing_val.map(deserialize_counter).unwrap_or_default();
    assert_eq!(key.len(), 32);
    for op in operands {
        let diff = deserialize_counter(op);
        assert!(diff == -1 || diff == 1);
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

fn write_opts() -> rocksdb_lib::WriteOptions {
    Default::default()
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

pub type RocksHandle<'a, D> = CachedHandle<RocksDatabaseHandle<'a, D>>;

impl<'a, D: Borrow<DB>> DbCounter for RocksHandle<'a, D> {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node(&self, key: H256, value: &[u8]) {
        let db = self.db.db.borrow();
        let mut write_batch = WriteBatch::default();
        if db.get(key.as_ref()).unwrap().is_none() {
            let rlp = Rlp::new(&value);
            let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
            trace!("inserting node {}=>{:?}", key, node);
            for hash in node.childs() {
                self.db.increase(&mut write_batch, hash);
            }

            write_batch.put(key.as_ref(), value);
            db.write_opt(write_batch, &write_opts())
                .expect("Cannot write batch to db");
        }
    }
    fn gc_count(&self, key: H256) -> usize {
        let val: i64 = self
            .db
            .db
            .borrow()
            .get_cf(&self.db.counter_cf, key.as_ref())
            .expect("Cannot request counter")
            .map(|s| deserialize_counter(&s))
            .unwrap_or_default();
        val as usize
    }

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node(&self, key: H256) -> Vec<H256> {
        let db = self.db.db.borrow();
        let mut nodes = vec![];

        if let Some(value) = db.get(key.as_ref()).unwrap() {
            let mut write_batch = WriteBatch::default();
            if self.gc_count(key) != 0 {
                return vec![];
            }
            write_batch.delete(key.as_ref());
            // mark counter as zero to rise conflict during apply write batch, if counter was increased.
            self.db.remove_counter(&mut write_batch, key);

            let rlp = Rlp::new(&value);
            let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
            for hash in node.childs() {
                if self.gc_count(hash) == 1 {
                    nodes.push(hash);
                }
                self.db.decrease(&mut write_batch, hash);
            }

            db.write_opt(write_batch, &write_opts())
                .expect("Cannot write batch to db");
        }
        nodes
    }

    fn gc_pin_root(&self, key: H256) {
        let mut write_batch = WriteBatch::default();
        self.db.increase(&mut write_batch, key);
        self.db
            .db
            .borrow()
            .write_opt(write_batch, &write_opts())
            .expect("cannot write batch")
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        let mut write_batch = WriteBatch::default();
        self.db.decrease(&mut write_batch, key);
        self.db
            .db
            .borrow()
            .write_opt(write_batch, &write_opts())
            .expect("cannot write batch");
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

    pub fn clear_cache(&mut self) {
        self.handle.clear_cache();
    }

    pub fn apply(self) -> Result<H256, String> {
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

    use crate::gc::TrieCollection;
    use crate::merkle::MerkleNode;
    use hex_literal::hex;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rlp::Rlp;
    use rocksdb_lib::{ColumnFamilyDescriptor, Options};
    use tempfile::tempdir;

    use super::*;
    use crate::impls::tests::{Data, K};

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
        let mut triedb = RocksMemoryTrieMut::new(&db, crate::empty_trie_hash(), cf);
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
        let root_1 = triedb.apply().unwrap();

        let mut triedb = RocksMemoryTrieMut::new(&db, root_1, cf);
        for (k, data) in kvs_2.iter() {
            triedb.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        let root_2 = triedb.apply().unwrap();

        assert_ne!(root_1, root_2);

        let triedb = RocksMemoryTrieMut::new(&db, root_2, cf);
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

        let mut collection =
            TrieCollection::new(RocksHandle::new(RocksDatabaseHandle::new(&db, cf)));

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        trie.insert(key3, value3);
        let patch = trie.into_patch();
        assert_eq!(collection.database.gc_count(patch.root), 0);
        let root = collection.apply_increase(patch);
        assert_eq!(collection.database.gc_count(root), 0);

        // mark root for pass GC
        collection.database.gc_pin_root(root);
        assert_eq!(collection.database.gc_count(root), 1);

        // CHECK CHILDS counts
        println!("root={}", root);
        let node = collection.database.get(root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let childs = node.childs();
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
        let another_root = collection.apply_increase(patch);
        assert_eq!(collection.database.gc_count(another_root), 0);

        // mark root for pass GC
        collection.database.gc_pin_root(another_root);
        assert_eq!(collection.database.gc_count(another_root), 1);

        let node = collection.database.get(another_root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let another_root_childs = node.childs();
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

        let latest_root = collection.apply_increase(patch);

        collection.database.gc_pin_root(latest_root);

        let node = collection.database.get(latest_root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let latest_root_childs = node.childs();
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

        let mut elems = collection.database.gc_cleanup_layer(&[root]);
        assert_eq!(elems.len(), 1);
        while !elems.is_empty() {
            // perform additional check, that all removed elements should be also removed from db.
            let cloned_elems = elems.clone();
            elems = collection.database.gc_cleanup_layer(&elems);
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

        let mut collection =
            TrieCollection::new(RocksHandle::new(RocksDatabaseHandle::new(&db, cf)));

        let mut root = crate::empty_trie_hash();
        let mut roots = BTreeSet::new();

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());

            let patch = trie.into_patch();
            root = collection.apply_increase(patch);

            if !roots.insert(root) {
                collection.database.gc_pin_root(root);
            }
        }

        // perform cleanup of all intermediate roots
        for stale_root in roots {
            if stale_root == root {
                continue;
            }
            let mut elems = collection.database.gc_cleanup_layer(&[stale_root]);
            while !elems.is_empty() {
                elems = collection.database.gc_cleanup_layer(&elems);
            }
        }

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
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
            let patch = trie.into_patch();
            root = collection.apply_increase(patch);
        }

        let trie = collection.trie_for(root);
        for k in kvs_2.keys() {
            assert_eq!(
                kvs_2[k],
                bincode::deserialize(&TrieMut::get(&trie, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        TestResult::passed()
    }
}
