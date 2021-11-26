use std::{collections::HashMap, num::NonZeroUsize};

use derive_more::{Add, AsRef, Deref, Display, Into};

use primitive_types::H256;

use crate::{delete, get, insert, Change, Database, TrieMut};
use crate::{MerkleNode, MerkleValue, Rlp};

pub trait RefCounter {
    fn increase(&mut self, key: H256);
    fn decrease(&mut self, key: H256);
    fn counts(&self, key: H256) -> usize;

    fn pin_root(&mut self, root: H256);
    /// Returns `true` if root tree data can be purged
    fn unpin_root(&mut self, root: H256) -> bool;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Into, Add, Display, AsRef, Deref)]
struct Counter(usize);

impl Counter {
    fn increase(&mut self) {
        self.0 += 1;
    }
}

#[derive(Debug, Default)]
struct ReachableHashes(HashMap<H256, Counter>);

impl ReachableHashes {
    fn collect(merkle_node: &MerkleNode) -> Self {
        let mut this = Self::default();
        this.process_node(merkle_node);
        this
    }

    fn process_node(&mut self, merkle_node: &MerkleNode) {
        match merkle_node {
            MerkleNode::Leaf(_, _) => {}
            MerkleNode::Extension(_, merkle_value) => {
                self.process_value(merkle_value);
            }
            MerkleNode::Branch(merkle_values, _) => {
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
            MerkleValue::Hash(hash) => self.0.entry(*hash).or_default().increase(),
        }
    }

    fn counters(&self) -> impl Iterator<Item = (H256, usize)> + '_ {
        self.0
            .iter()
            .map(|(hash, counter)| (*hash, usize::from(*counter)))
    }
}

pub trait DatabaseMut: Database {
    // TODO: remove Option, remove keys explicitly
    fn set(&mut self, key: H256, value: Option<&[u8]>);
}

pub struct TrieCollection<Db, Rc> {
    db: Db,
    rc: Rc,
}

impl<Db, Rc> TrieCollection<Db, Rc> {
    fn new(db: Db, rc: Rc) -> Self {
        Self { db, rc }
    }
}

impl<Db, Rc> TrieCollection<Db, Rc>
where
    Db: DatabaseMut,
{
    pub fn trie_for(&self, root: H256) -> DatabaseTrieMut<'_, Db> {
        DatabaseTrieMut {
            database: &self.db,
            change: Change::default(),
            root,
        }
    }
}

impl<Db, Rc> TrieCollection<Db, Rc>
where
    Db: DatabaseMut,
    Rc: RefCounter,
{
    pub fn apply(&mut self, DatabaseTrieMutPatch { change, root }: DatabaseTrieMutPatch) -> H256 {
        for key in change.removes {
            let bytes = self.db.get(key);
            let rlp = Rlp::new(bytes);
            let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
            let hashes = ReachableHashes::collect(&node);
            for (hash, counts) in hashes.counters() {
                for _ in 0..counts {
                    self.rc.decrease(hash); // TODO: pass count as argumentc
                }
            }
        }

        for (key, value) in change.adds {
            self.db.set(key, Some(&value));

            // TODO: refactor it for avoid decoding bytes of previously encoded value
            {
                let rlp = Rlp::new(&value);
                let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                let hashes = ReachableHashes::collect(&node);
                for (hash, counts) in hashes.counters() {
                    for _ in 0..counts {
                        self.rc.increase(hash); // TODO: pass count as argument
                    }
                }
            }
        }

        // self.rc.pin_root(root);

        root
    }

    pub fn purge(&mut self, root: H256) {
        if self.rc.unpin_root(root) {
            self.rm_sub_tree_keys(root);
        }
    }

    fn rm_sub_tree_keys(&mut self, key: H256) {
        let bytes = self.db.get(key);
        let rlp = Rlp::new(bytes);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let hashes = ReachableHashes::collect(&node);

        for (key, _) in hashes.counters() {
            if self.rc.counts(key) == 0 {
                self.db.set(key, None);
            }
        }
    }
}

pub struct DatabaseTrieMut<'a, Db> {
    database: &'a Db,
    change: Change,
    root: H256,
}

pub struct DatabaseTrieMutPatch {
    root: H256,
    change: Change,
}

// TODO: impl DatabaseMut for DatabaseTrieMut and lookup changes before database

impl<'a, Db: Database> TrieMut for DatabaseTrieMut<'a, Db> {
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
        // XXX: should we check remove before db lookup?
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
    use std::collections::{hash_map::Entry, HashMap, HashSet};

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::*;
    use crate::impls::tests::{Data, K};

    impl Counter {
        fn decrease(&mut self) {
            self.0 -= 1;
        }

        fn is_zero(&self) -> bool {
            self.0 == 0
        }
    }

    impl PartialEq<usize> for Counter {
        fn eq(&self, value: &usize) -> bool {
            &self.0 == value
        }
    }

    #[derive(Debug, Default)]
    struct Counters {
        keys: HashMap<H256, Counter>,
        roots: HashMap<H256, Counter>,
    }

    impl RefCounter for Counters {
        fn increase(&mut self, key: H256) {
            let counter = self.keys.entry(key).or_default();
            counter.increase();
            println!("{} ++count = {}", key, counter);
        }

        fn decrease(&mut self, key: H256) {
            let counter = match self.keys.get_mut(&key) {
                Some(counter) => counter,
                None => panic!("decreasing non-existing key {}", key),
            };
            counter.decrease();
            println!("{} --count = {}", key, counter);
        }

        fn counts(&self, key: H256) -> usize {
            if let Some(counter) = self.keys.get(&key) {
                usize::from(*counter)
            } else {
                panic!("unable to counts non-existing key {}", key)
            }
        }

        fn pin_root(&mut self, root: H256) {
            let counter = self.roots.entry(root).or_default();
            counter.increase();
            println!("{} root = {}", root, counter);
        }

        fn unpin_root(&mut self, root: H256) -> bool {
            let counter = match self.roots.get_mut(&root) {
                Some(counter) => counter,
                None => panic!("unpinng non-existing root {}", root),
            };
            counter.decrease();
            counter.is_zero()
        }
    }

    #[test]
    fn it_handles_keys_and_roots_as_expected() {
        let key = b"0xcafe";
        let value = b"0xcode";
        let another_value = b"0xbabe";

        let mut collection = TrieCollection::new(HashMap::new(), Counters::default());

        // First modification
        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key, value);
        let patch = trie.into_patch();

        assert!(patch.change.removes.is_empty());
        let first_mod_added_keys: HashSet<H256> = dbg!(patch.change.adds.keys().copied().collect());
        assert!(!first_mod_added_keys.is_empty());

        let root = collection.apply(patch);
        assert_eq!(collection.rc.keys.get(&root), None);
        assert_eq!(collection.rc.roots.get(&root), None);
        collection.rc.pin_root(root);
        assert_eq!(collection.rc.roots[&root], 1);
        dbg!(&collection.rc);
        dbg!(&collection.db);

        // Second modification
        let mut trie = collection.trie_for(root);
        assert_eq!(TrieMut::get(&trie, key), Some(value.to_vec()));
        trie.insert(key, another_value);
        assert_eq!(TrieMut::get(&trie, key), Some(another_value.to_vec()));

        let patch = trie.into_patch();
        let second_mod_added_keys: HashSet<H256> =
            dbg!(patch.change.adds.keys().copied().collect());
        let second_mod_removed_keys: HashSet<H256> =
            dbg!(patch.change.removes.iter().copied().collect());

        assert!(!second_mod_added_keys.is_empty());
        assert!(!second_mod_removed_keys.is_empty());

        let another_root = collection.apply(patch);
        assert_eq!(collection.rc.roots.get(&another_root), None);
        assert_eq!(collection.rc.keys.get(&another_root), None);
        collection.rc.pin_root(another_root);
        assert_eq!(collection.rc.roots[&another_root], 1);

        // Okay, both roots are alive
        assert_eq!(
            TrieMut::get(&collection.trie_for(root), key),
            Some(value.to_vec())
        );
        assert_eq!(
            TrieMut::get(&collection.trie_for(another_root), key),
            Some(another_value.to_vec())
        );

        // Remove first root
        // assert!(collection.rc.unpin_root(root));
        dbg!(&collection.rc);
        dbg!(&collection.db);
        collection.purge(root);

        dbg!(&collection.rc);
        dbg!(&collection.db);

        // panic!();

        // // assert_eq!(collection.rc.decrease(root), 0);
        // assert_eq!(
        //     TrieMut::get(&collection.trie_for(another_root), key),
        //     Some(another_value.to_vec())
        // );
    }

    #[quickcheck]
    fn qc_handles_several_roots_via_gc(
        kvs_1: HashMap<K, Data>,
        kvs_2: HashMap<K, Data>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }

        let mut collection = TrieCollection::new(HashMap::new(), Counters::default());

        let mut root = crate::empty_trie_hash();
        let mut roots = vec![];

        for (key, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            let key_bytes = key.to_bytes();
            let data_bytes = bincode::serialize(data).unwrap();

            trie.insert(&key_bytes, &data_bytes);
            let patch = trie.into_patch();
            root = collection.apply(patch);

            collection.rc.pin_root(root);
            roots.push(root);
        }

        let trie = collection.trie_for(root);
        for key in kvs_1.keys() {
            let key_bytes = key.to_bytes();
            let data_bytes = TrieMut::get(&trie, &key_bytes).unwrap();
            let data: Data = bincode::deserialize(&data_bytes).unwrap();
            assert_eq!(data, kvs_1[key]);
        }

        roots
            .iter()
            .rev()
            .skip(1)
            .for_each(|root| collection.purge(*root));
        roots.clear();

        let trie = collection.trie_for(root);
        for key in kvs_1.keys() {
            let key_bytes = key.to_bytes();
            let data_bytes = TrieMut::get(&trie, &key_bytes).unwrap();
            let data: Data = bincode::deserialize(&data_bytes).unwrap();
            assert_eq!(data, kvs_1[key]);
        }

        for (key, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            let key_bytes = key.to_bytes();
            let data_bytes = bincode::serialize(data).unwrap();

            trie.insert(&key_bytes, &data_bytes);
            let patch = trie.into_patch();
            root = collection.apply(patch);
            roots.push(root);
        }

        let trie = collection.trie_for(root);

        for key in kvs_1.keys().filter(|key| !kvs_2.contains_key(key)) {
            let key_bytes = key.to_bytes();
            let data_bytes = TrieMut::get(&trie, &key_bytes).unwrap();
            let data: Data = bincode::deserialize(&data_bytes).unwrap();
            assert_eq!(data, kvs_1[key]);
        }
        for key in kvs_2.keys() {
            let key_bytes = key.to_bytes();
            let data_bytes = TrieMut::get(&trie, &key_bytes).unwrap();
            let data: Data = bincode::deserialize(&data_bytes).unwrap();
            assert_eq!(data, kvs_2[key]);
        }

        TestResult::passed()
    }
}
