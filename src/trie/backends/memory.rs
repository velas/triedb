#![allow(unused)] // FIXME: delete this line

use std::{
    borrow::Cow,
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    marker::PhantomData,
    sync::Arc,
    vec::IntoIter,
};

use dashmap::{mapref::entry::Entry, DashMap};
use derivative::*;
use log::trace;
use primitive_types::H256;
use rlp::Rlp;

use crate::{
    cache::CachedHandle,
    database::{Database, DatabaseMut},
    empty_trie_hash,
    merkle::{MerkleNode, MerkleValue},
    CachedDatabaseHandle,
};

struct HashIterator;

impl HashIterator {
    pub fn collect<F: Fn(&[u8]) -> Vec<H256> + Clone>(
        merkle_node: &MerkleNode,
        child_extractor: F,
    ) -> Vec<H256> {
        Self::process_node(merkle_node, child_extractor)
            .filter(|i| *i != empty_trie_hash!())
            .collect()
    }

    fn process_node<F: Fn(&[u8]) -> Vec<H256> + Clone>(
        merkle_node: &MerkleNode,
        child_extractor: F,
    ) -> IntoIter<H256> {
        match merkle_node {
            MerkleNode::Leaf(_, d) => (child_extractor)(*d).into_iter(),
            MerkleNode::Extension(_, merkle_value) => {
                Self::process_value(merkle_value, child_extractor)
            }
            MerkleNode::Branch(merkle_values, data) => {
                // if let Some(d) = data {
                //     self.childs.extend_from_slice(&(self.child_extractor)(*d))
                // }
                // for merkle_value in merkle_values {
                //     self.process_value(merkle_value);
                // }
                merkle_values
                    .iter()
                    .map(|merkle_value| Self::process_value(merkle_value, child_extractor.clone()))
                    .fold(Vec::new(), |mut acc, next| {
                        acc.extend_from_slice(next.as_slice());
                        acc
                    })
                    .into_iter()
            }
        }
    }

    fn process_value<F: Fn(&[u8]) -> Vec<H256> + Clone>(
        merkle_value: &MerkleValue,
        child_extractor: F,
    ) -> IntoIter<H256> {
        match merkle_value {
            MerkleValue::Empty => vec![].into_iter(),
            MerkleValue::Full(merkle_node) => Self::process_node(merkle_node, child_extractor),
            MerkleValue::Hash(hash) => vec![*hash].into_iter(),
        }
    }
}

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

#[derive(Debug, Default)]
pub struct MemoryBackend {
    counter: DashMap<H256, usize>,
    data: DashMap<H256, Vec<u8>>,
}

impl MemoryBackend {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

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

// TODO: Review impl pls
impl CachedDatabaseHandle for Arc<MemoryBackend> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.data
            .get(&key)
            .map(|x| x.value().clone())
            .unwrap()
            .to_vec()
    }
}

impl DatabaseMut for CachedHandle<Arc<MemoryBackend>> {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        match self.db.data.entry(key) {
            Entry::Occupied(_) => {}
            Entry::Vacant(v) => {
                let rlp = Rlp::new(value);
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
            Entry::Occupied(entry) if self.gc_count(key) == 0 => {
                // in this code we lock data, so it's okay to check counter from separate function
                let value = entry.remove();
                let rlp = Rlp::new(&value);
                let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");

                ReachableHashes::collect(&node, child_extractor)
                    .childs()
                    .into_iter()
                    .filter(|k| self.db.decrease(*k) == 0)
                    .collect()
            }
            _ => vec![],
        }
    }

    fn gc_pin_root(&self, key: H256) {
        self.db.increase(key);
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        self.db.decrease(key) == 0
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
    // use crate::impls::tests::{Data, K}; // TODO
    use hex_literal::hex;

    use crate::{empty_trie_hash, trie::TrieHandle};

    use std::str::FromStr;

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

    #[test]
    fn trie_middle_leaf() {
        let mut map = HashMap::new();
        map.insert(
            "key1aa".as_bytes().to_vec(),
            "0123456789012345678901234567890123456789xxx"
                .as_bytes()
                .to_vec(),
        );
        map.insert(
            "key1".as_bytes().to_vec(),
            "0123456789012345678901234567890123456789Very_Long"
                .as_bytes()
                .to_vec(),
        );
        map.insert("key2bb".as_bytes().to_vec(), "aval3".as_bytes().to_vec());
        map.insert("key2".as_bytes().to_vec(), "short".as_bytes().to_vec());
        map.insert("key3cc".as_bytes().to_vec(), "aval3".as_bytes().to_vec());
        map.insert(
            "key3".as_bytes().to_vec(),
            "1234567890123456789012345678901".as_bytes().to_vec(),
        );

        let btrie =
            TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::build(&map, |data: &[u8]| vec![]);

        assert_eq!(
            btrie.root(),
            H256::from_str("cb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89")
                .unwrap()
        );
        assert_eq!(
            btrie.get("key2bb".as_bytes(), no_childs),
            Some("aval3".as_bytes().to_vec())
        );
        assert_eq!(btrie.get("key2bbb".as_bytes(), no_childs), None);

        let mut mtrie = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();
        for (key, value) in &map {
            mtrie.insert(key, value, no_childs);
        }

        dbg!(&btrie.database());
        dbg!(&mtrie.database());

        // assert_eq!(btrie.database(), mtrie.database()); // FIXME: uncomment?

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes(), no_childs);
        mtrie.delete("key2bbb".as_bytes(), |_| vec![]);

        // assert_eq!(btrie.database(), mtrie.database()); // FIXME: uncomment?

        for key in map.keys() {
            mtrie.delete(key, |_| vec![]);
        }

        // assert!(mtrie.database().is_empty()); // FIXME: uncomment?
        assert!(mtrie.root == empty_trie_hash!());
    }

    #[test]
    fn trie_two_keys() {
        let mut mtrie = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();
        mtrie.insert("key1".as_bytes(), "aval1".as_bytes(), no_childs);
        mtrie.insert("key2bb".as_bytes(), "aval3".as_bytes(), no_childs);
        let db1 = mtrie.database().clone();

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes(), no_childs);
        mtrie.delete("key2bbb".as_bytes(), |_| vec![]);

        // assert_eq!(db1, mtrie.database()); // FIXME: uncomment?
    }

    #[test]
    fn trie_multiple_prefixed_keys() {
        let key1 = &hex!("af");
        let key2 = &hex!("a2");
        let key3 = &hex!("b3");
        let keyc = &hex!("bf");
        let val = &hex!("bb");
        let mut mtrie = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();
        mtrie.insert(key1, val, no_childs);
        mtrie.insert(key2, val, no_childs);
        mtrie.insert(key3, val, no_childs);
        mtrie.insert(keyc, val, no_childs);
        mtrie.delete(keyc, |_| vec![]);

        assert_eq!(mtrie.get(key1, no_childs).unwrap(), val);
        assert_eq!(mtrie.get(key2, no_childs).unwrap(), val);
        assert_eq!(mtrie.get(key3, no_childs).unwrap(), val);
        assert!(mtrie.get(keyc, no_childs).is_none());
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

    // #[cfg(disabled)]
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

        let collection = TrieHandle::<CachedHandle<Arc<MemoryBackend>>>::default();

        // let mut trie = collection.trie_for(crate::empty_trie_hash());
        let trie = collection; // TODO: cleanup
        trie.insert(key1, value1, no_childs);
        trie.insert(key2, value2, no_childs);
        trie.insert(key3, value3, no_childs);
        let patch = trie.into_patch();
        assert_eq!(collection.database().gc_count(patch.root), 0);
        let root_guard = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database().gc_count(root_guard.root), 1);

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

    #[cfg(disabled)]
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

    #[cfg(disabled)]
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

    #[cfg(disabled)]
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
