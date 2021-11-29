use crate::{delete, get, insert, Change, Database, TrieMut};
use primitive_types::H256;

pub trait DbCounter {
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node(&self, key: H256, value: &[u8]);

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node(&self, key: H256) -> Vec<H256>;

    // increase root link count
    fn gc_pin_root(&self, root: H256);

    // return true if root can be cleanedup.
    fn gc_unpin_root(&self, root: H256) -> bool;

    // Introspection only:
    // Return count of references to key.
    // Should not be used in underlying modification,
    // To modify counter use gc_insert_node/gc_try_cleanup_node.
    fn gc_count(&self, key: H256) -> usize;

    // Any of remove is a link to MerkleNode.
    // Every remove should be processed atomicly:
    // 1. checks if removes counter == 0.
    // 2. if it == 0 remove from database, and decrement child counters.
    // 3. return list of childs with counter == 0
    fn gc_cleanup_layer(&mut self, removes: &[H256]) -> Vec<H256> {
        let mut result = Vec::new();
        for remove in removes {
            result.extend_from_slice(&self.gc_try_cleanup_node(*remove))
        }
        result
    }
}

pub struct TrieCollection<D> {
    database: D,
}

impl<D: DbCounter> TrieCollection<D> {
    pub fn new(database: D) -> Self {
        Self { database }
    }

    pub fn trie_for(&self, root: H256) -> DatabaseTrieMut<'_, D> {
        DatabaseTrieMut {
            database: &self.database,
            change: Change::default(),
            root,
        }
    }

    // Apply changes and only increase child counters
    pub fn apply_increase(
        &mut self,
        DatabaseTrieMutPatch { root, change }: DatabaseTrieMutPatch,
    ) -> H256 {
        for (key, value) in change.adds {
            self.database.gc_insert_node(key, &value);
            // self.database.set(key, Some(&value));
            // let rlp = Rlp::new(&value);
            // let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");

            // for hash in node.childs() {
            //     self.counter.increase(hash); // TODO: pass count as argument
            // }
        }
        root
    }
}

pub struct DatabaseTrieMut<'a, D> {
    database: &'a D,
    change: Change,
    root: H256,
}

pub struct DatabaseTrieMutPatch {
    root: H256,
    change: Change,
}

// TODO: impl DatabaseMut for DatabaseTrieMut and lookup changes before database

impl<'a, D: Database> TrieMut for DatabaseTrieMut<'a, D> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, self, key, value);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, self, key);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, self, key).map(|v| v.into())
    }
}

impl<'a, D: Database> Database for DatabaseTrieMut<'a, D> {
    fn get(&self, key: H256) -> &[u8] {
        if let Some(bytes) = self.change.adds.get(&key) {
            bytes
        } else {
            self.database.get(key)
        }
    }
}

impl<'a, D> DatabaseTrieMut<'a, D> {
    pub fn into_patch(self) -> DatabaseTrieMutPatch {
        let Self { root, change, .. } = self;
        DatabaseTrieMutPatch { root, change }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use dashmap::{mapref::entry::Entry, DashMap};

    use crate::MerkleNode;
    use log::*;
    use rlp::Rlp;

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::*;
    use crate::{
        cache::CachedHandle,
        impls::tests::{Data, K},
        CachedDatabaseHandle,
    };
    use hex_literal::hex;

    #[derive(Default)]
    struct MapWithCounter {
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

    type MapWithCounterCached = CachedHandle<MapWithCounter>;

    impl DbCounter for MapWithCounterCached {
        // Insert value into db.
        // Check if value exist before, if not exist, increment child counter.
        fn gc_insert_node(&self, key: H256, value: &[u8]) {
            match self.db.data.entry(key) {
                Entry::Occupied(_) => {}
                Entry::Vacant(v) => {
                    let rlp = Rlp::new(&value);
                    let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                    trace!("inserting node {}=>{:?}", key, node);
                    for hash in node.childs() {
                        self.db.increase(hash);
                    }
                    v.insert(value.to_vec());
                }
            };
        }
        fn gc_count(&self, key: H256) -> usize {
            self.db.counter.get(&key).map(|v| *v).unwrap_or_default()
        }

        // atomic operation:
        // 1. check if key counter didn't increment in other thread.
        // 2. remove key if counter == 0.
        // 3. find all childs
        // 4. decrease child counters
        // 5. return list of childs with counter == 0
        fn gc_try_cleanup_node(&self, key: H256) -> Vec<H256> {
            match self.db.data.entry(key) {
                Entry::Occupied(entry) => {
                    // in this code we lock data, so it's okay to check counter from separate function
                    if self.gc_count(key) == 0 {
                        let value = entry.remove();
                        let rlp = Rlp::new(&value);
                        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                        return node
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

    impl CachedDatabaseHandle for MapWithCounter {
        fn get(&self, key: H256) -> Vec<u8> {
            self.data.get(&key).unwrap().clone()
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

        let mut collection = TrieCollection::new(MapWithCounterCached::default());

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

    #[quickcheck]
    fn qc_handles_several_roots_via_gc(
        kvs_1: HashMap<K, Data>,
        kvs_2: HashMap<K, Data>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }
        let mut collection = TrieCollection::new(MapWithCounterCached::default());

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
        println!(
            "db_size_before_cleanup = {}\n\
            counters = {}",
            collection.database.db.data.len(),
            collection.database.db.counter.len()
        );

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
