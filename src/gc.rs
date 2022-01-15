use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::database::{Database, DatabaseMut};
use crate::merkle::MerkleValue;
use crate::MerkleNode;
use crate::{
    cache::CachedHandle, delete, empty_trie_hash, get, insert, CachedDatabaseHandle, Change,
    TrieMut,
};

//use asterix to avoid unresolved import https://github.com/rust-analyzer/rust-analyzer/issues/7459#issuecomment-907714513
use dashmap::{mapref::entry::Entry, DashMap};
use derivative::*;
use log::*;
use primitive_types::H256;
use rlp::Rlp;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct ReachableHashes<F> {
    childs: Vec<H256>,
    #[derivative(Debug = "ignore")]
    child_extractor: F,
}

impl<F> ReachableHashes<F>
where
    F: FnMut(&[u8]) -> Vec<H256>,
{
    pub fn collect(merkle_node: &MerkleNode, child_extractor: F) -> Self {
        let mut this = Self {
            childs: Default::default(),
            child_extractor,
        };
        this.process_node(merkle_node);
        this
    }

    fn process_node(&mut self, merkle_node: &MerkleNode) {
        match merkle_node {
            MerkleNode::Leaf(_, d) => self.childs.extend_from_slice(&(self.child_extractor)(*d)),
            MerkleNode::Extension(_, merkle_value) => {
                self.process_value(merkle_value);
            }
            MerkleNode::Branch(merkle_values, data) => {
                if let Some(d) = data {
                    self.childs.extend_from_slice(&(self.child_extractor)(*d))
                }
                for merkle_value in merkle_values {
                    self.process_value(merkle_value);
                }
            }
        }
    }

    fn process_value(&mut self, merkle_value: &MerkleValue) {
        match merkle_value {
            MerkleValue::Empty => {}
            MerkleValue::Full(merkle_node) => self.process_node(merkle_node),
            MerkleValue::Hash(hash) => self.childs.push(*hash),
        }
    }

    pub fn childs(self) -> Vec<H256> {
        self.childs
            .into_iter()
            // Empty trie is a common default value for most
            // objects that contain submap, filtering it will reduce collissions.
            .filter(|i| *i != empty_trie_hash!())
            .collect()
    }
}

pub struct TrieCollection<D> {
    pub database: D,
}

impl<D: Database + DatabaseMut> TrieCollection<D> {
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

impl<D: Database> Database for DatabaseTrieMut<D> {
    fn get(&self, key: H256) -> &[u8] {
        if let Some(bytes) = self.change_data.get(&key) {
            &**bytes
        } else {
            self.database.borrow().get(key)
        }
    }
}

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

#[derive(Default)]
pub struct MapWithCounter {
    counter: DashMap<H256, usize>,
    data: DashMap<H256, Vec<u8>>,
}
impl MapWithCounter {
    fn increase(&self, key: H256) -> usize {
        self.counter
            .entry(key)
            .and_modify(|count| {
                *count += 1;
            })
            .or_insert(1);
        trace!("{} count++ is {}", key, *self.counter.get(&key).unwrap());
        *self.counter.get(&key).unwrap()
    }
    fn decrease(&self, key: H256) -> usize {
        let count = match self.counter.entry(key) {
            Entry::Vacant(_) => unreachable!(),
            Entry::Occupied(entry) if *entry.get() <= 1 => {
                entry.remove();
                0
            }
            Entry::Occupied(mut entry) => {
                *entry.get_mut() -= 1;
                *entry.get()
            }
        };
        trace!("{} count-- is {}", key, count);
        count
    }
}

pub type MapWithCounterCached = CachedHandle<Arc<MapWithCounter>>;

impl DatabaseMut for MapWithCounterCached {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        match self.db.data.entry(key) {
            Entry::Occupied(_) => {}
            Entry::Vacant(v) => {
                let rlp = Rlp::new(&value);
                let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                trace!("inserting node {}=>{:?}", key, node);
                for hash in ReachableHashes::collect(&node, child_extractor).childs() {
                    self.db.increase(hash);
                }
                v.insert(value.to_vec());
            }
        };
    }
    fn gc_count(&self, key: H256) -> usize {
        self.db.counter.get(&key).map(|v| *v).unwrap_or_default()
    }

    // Return true if node data is exist, and it counter more than 0;
    fn node_exist(&self, key: H256) -> bool {
        self.db.data.get(&key).is_some() && self.gc_count(key) > 0
    }

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node<F>(&self, key: H256, child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        match self.db.data.entry(key) {
            Entry::Occupied(entry) => {
                // in this code we lock data, so it's okay to check counter from separate function
                if self.gc_count(key) == 0 {
                    let value = entry.remove();
                    let rlp = Rlp::new(&value);
                    let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                    return ReachableHashes::collect(&node, child_extractor)
                        .childs()
                        .into_iter()
                        .filter(|k| self.db.decrease(*k) == 0)
                        .collect();
                }
            }
            Entry::Vacant(_) => {}
        };
        vec![]
    }

    fn gc_pin_root(&self, key: H256) {
        self.db.increase(key);
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        self.db.decrease(key) == 0
    }
}

impl CachedDatabaseHandle for Arc<MapWithCounter> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.data
            .get(&key)
            .unwrap_or_else(|| panic!("Value for {} not found in database", key))
            .clone()
    }
}

pub struct RootGuard<'a, D: Database + DatabaseMut, F: FnMut(&[u8]) -> Vec<H256>> {
    pub root: H256,
    db: &'a D,
    child_collector: F,
}
impl<'a, D: Database + DatabaseMut, F: FnMut(&[u8]) -> Vec<H256>> RootGuard<'a, D, F> {
    pub fn new(db: &'a D, root: H256, child_collector: F) -> Self {
        if root != empty_trie_hash!() {
            db.gc_pin_root(root);
        }
        Self {
            db,
            root,
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

impl<'a, D: Database + DatabaseMut, F: FnMut(&[u8]) -> Vec<H256>> Drop for RootGuard<'a, D, F> {
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

#[cfg(test)]
pub mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::Arc,
    };

    use crate::{
        merkle::nibble::{into_key, Nibble},
        MerkleNode,
    };
    use rlp::Rlp;

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use quickcheck::{Arbitrary, Gen};
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::impls::tests::{Data, K};
    use hex_literal::hex;

    fn no_childs(_: &[u8]) -> Vec<H256> {
        vec![]
    }

    /// short fixed lenght key, with 4 nimbles
    /// To simplify fuzzying each nimble is one of [0,3,7,b,f]
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    pub struct Key(pub [u8; 4]);

    impl Arbitrary for Key {
        fn arbitrary(g: &mut Gen) -> Self {
            let nibble: Vec<_> = std::iter::from_fn(|| {
                g.choose(&[Nibble::N0, Nibble::N3, Nibble::N7, Nibble::N11, Nibble::N15])
                    .copied()
            })
            .take(8)
            .collect();
            let mut key = [0; 4];

            let vec_data = into_key(&nibble);
            assert_eq!(key.len(), vec_data.len());
            key.copy_from_slice(&vec_data);

            Self(key)
        }
    }

    /// RLP encoded data should be more or equal 32 bytes, this prevent node data to be inlined.
    /// There is two kind of datas, 1st byte == 0xff and == 0x00, remaining always stay 0x00
    #[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Eq, Debug)]
    pub struct FixedData(pub [u8; 32]);

    impl Arbitrary for FixedData {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut fixed = [0; 32]; // increase possibility of conflict.
            if <bool>::arbitrary(g) {
                fixed[0] = 0xff
            }
            Self(fixed)
        }
    }

    // Visualisation of the next tree::
    // 'bbaa' -> "same data",
    // 'ffaa' -> "same data",
    // 'bbcc' -> "other data"
    // 'bbcc' -> "Changed data"

    // And 1stroot -> bbaa, ffaa, bbcc(1)
    // 2nd root -> bbaa, ffaa, bbcc(2)
    //
    // expecting all values to be leafs
    // And branch values to be build on top.
    //

    //
    // Note: in real world there will be extension node between bb and roots. But for visualisation of trie it's still nice.
    //
    // ┌────┐┌────────────┐┌───────────┐
    // │root││another_root││latest_root│
    // └──┬┬┘└┬────────┬──┘└┬─┬────────┘
    //   ┌││──┘        │    │ │
    //   ││└──┐       ┌│────┘ │
    // ┌─▽▽─┐┌▽───┐┌──▽▽┐┌────▽┐
    // │ffaa││bb  ││bb* ││ffaa*│
    // └────┘└┬──┬┘└┬──┬┘└─────┘
    // ┌──────▽┐┌▽──▽┐┌▽────┐
    // │bbcc   ││bbaa││bbcc*│
    // └───────┘└────┘└─────┘

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

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        trie.insert(key3, value3);
        let patch = trie.into_patch();
        assert_eq!(collection.database.gc_count(patch.root), 0);
        let root_guard = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database.gc_count(root_guard.root), 1);

        // CHECK CHILDS counts
        println!("root={}", root_guard.root);
        let node = collection.database.get(root_guard.root);
        let rlp = Rlp::new(&node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(childs.len(), 2); // "bb..", "ffaa", check test doc comments

        for child in &childs {
            assert_eq!(collection.database.gc_count(*child), 1);
        }

        let mut trie = collection.trie_for(root_guard.root);
        assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
        assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
        assert_eq!(TrieMut::get(&trie, key3), Some(value3.to_vec()));

        trie.insert(key3, value3_1);
        assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));
        let patch = trie.into_patch();

        assert_eq!(collection.database.gc_count(patch.root), 0);
        let another_root = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database.gc_count(another_root.root), 1);

        let node = collection.database.get(another_root.root);
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

        let mut trie = collection.trie_for(another_root.root);

        // adding dublicate value should not affect RC
        trie.insert(key1, value1);

        let patch = trie.into_patch();
        assert_eq!(patch.root, another_root.root);

        // adding one more changed element, and make additional conflict.

        let mut trie = collection.trie_for(another_root.root);

        trie.insert(key2, value2_1);

        let patch = trie.into_patch();

        let latest_root = collection.apply_increase(patch, no_childs);

        let node = collection.database.get(latest_root.root);
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

        let root = root_guard.root;
        // return back
        collection.database.gc_pin_root(root_guard.root);
        assert!(!collection.database.gc_unpin_root(root_guard.root));

        collection.database.gc_pin_root(root_guard.root);
        drop(root_guard); // after drop manual unpin should free latest reference.

        // TRY cleanup first root.

        assert!(collection.database.gc_unpin_root(root));
        let mut elems = collection.database.gc_cleanup_layer(&[root], no_childs);
        assert_eq!(elems.len(), 1);
        while !elems.is_empty() {
            // perform additional check, that all removed elements should be also removed from db.
            let cloned_elems = elems.clone();
            elems = collection.database.gc_cleanup_layer(&elems, no_childs);
            for child in cloned_elems {
                assert!(collection.database.db.data.get(&child).is_none());
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

            assert!(collection.database.db.data.get(child).is_none());
        }
    }

    #[test]
    fn two_threads_conflict() {
        let shared_db = Arc::new(MapWithCounter::default());
        fn routine(db: Arc<MapWithCounter>) {
            let shared_db = CachedHandle::new(db);
            let key1 = &hex!("bbaa");
            let key2 = &hex!("ffaa");
            let key3 = &hex!("bbcc");

            // make data too long for inline
            let value1 = b"same data________________________";
            let value2 = b"same data________________________";
            let value3 = b"other data_______________________";
            let value3_1 = b"changed data_____________________";
            let collection = TrieCollection::new(shared_db);

            let mut trie = collection.trie_for(crate::empty_trie_hash());
            trie.insert(key1, value1);
            trie.insert(key2, value2);
            trie.insert(key3, value3);
            let patch = trie.into_patch();
            let mut root_guard = collection.apply_increase(patch, no_childs);

            let mut trie = collection.trie_for(root_guard.root);
            assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
            assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
            assert_eq!(TrieMut::get(&trie, key3), Some(value3.to_vec()));

            trie.insert(key3, value3_1);
            assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));
            let patch = trie.into_patch();

            root_guard = collection.apply_increase(patch, no_childs);

            let mut trie = collection.trie_for(root_guard.root);
            assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
            assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
            assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));

            trie.delete(key2);
            let patch = trie.into_patch();
            root_guard = collection.apply_increase(patch, no_childs);

            let trie = collection.trie_for(root_guard.root);

            assert_eq!(TrieMut::get(&trie, key2), None);
        }
        let cloned_db = shared_db.clone();
        let th1 = std::thread::spawn(move || {
            for _i in 0..100 {
                routine(cloned_db.clone())
            }
        });
        let cloned_db = shared_db.clone();
        let th2 = std::thread::spawn(move || {
            for _i in 0..100 {
                routine(cloned_db.clone())
            }
        });
        th1.join().unwrap();
        th2.join().unwrap();

        assert_eq!(shared_db.data.len(), 0);
        assert_eq!(shared_db.counter.len(), 0);
    }

    #[quickcheck]
    fn qc_handles_several_key_changes(
        kvs_1: HashMap<Key, FixedData>,
        kvs_2: HashMap<Key, FixedData>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }
        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut root = crate::empty_trie_hash();
        let mut roots = Vec::new();

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.0, &data.0);

            let patch = trie.into_patch();
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;

            roots.push(root_guard);
        }
        println!(
            "db_size_before_cleanup = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );
        let last_root_guard = roots.pop().unwrap();

        // perform cleanup of all intermediate roots

        drop(roots);

        println!(
            "db_size_after_cleanup = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );

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
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;

            roots.push(root_guard);
        }

        let second_collection_root_guard = roots.pop().unwrap();
        // perform cleanup of all intermediate roots
        for stale_root in roots {
            drop(stale_root);
        }

        let trie = collection.trie_for(last_root_guard.root);
        for k in kvs_1.keys() {
            assert_eq!(&kvs_1[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        let trie = collection.trie_for(second_collection_root_guard.root);
        for k in kvs_2.keys() {
            assert_eq!(&kvs_2[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        println!(
            "db_size_with_two_colelctions = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );

        drop(last_root_guard);
        drop(second_collection_root_guard);

        println!(
            "db_size_after_all_cleanup = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );

        assert_eq!(collection.database.db.data.len(), 0);
        assert_eq!(collection.database.db.counter.len(), 0);

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
        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut root = crate::empty_trie_hash();
        let mut roots = Vec::new();

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());

            let patch = trie.into_patch();
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;

            roots.push(root_guard);
        }
        println!(
            "db_size_before_cleanup = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );

        let last_root = roots.pop().unwrap();
        // perform cleanup of all intermediate roots
        drop(roots);

        println!(
            "db_size_after_cleanup = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );
        // expect for kvs to be available
        let trie = collection.trie_for(root);
        for k in kvs_1.keys() {
            assert_eq!(
                kvs_1[k],
                bincode::deserialize(&TrieMut::get(&trie, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        let mut roots = Vec::new();
        for (k, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
            let patch = trie.into_patch();
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;

            roots.push(root_guard);
        }
        drop(last_root);

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
