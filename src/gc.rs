use primitive_types::H256;

use crate::{delete, get, insert, Change, DatabaseHandle as Database, TrieMut};

pub trait ItemCounter {
    fn increase(&mut self, key: H256) -> usize;
    fn decrease(&mut self, key: H256) -> usize;
}

pub trait DatabaseMut: Database {
    fn set(&mut self, key: H256, value: Option<&[u8]>);
}

pub struct TrieCollection<D: DatabaseMut, C: ItemCounter> {
    database: D,
    counter: C,
}

impl<D: DatabaseMut, C: ItemCounter> TrieCollection<D, C> {
    pub fn new(database: D, counter: C) -> Self {
        Self { database, counter }
    }

    pub fn trie_for(&self, root: H256) -> DatabaseTrieMut<'_, D> {
        DatabaseTrieMut {
            database: &self.database,
            change: Change::default(),
            root,
        }
    }

    pub fn apply(&mut self, DatabaseTrieMutPatch { root, change }: DatabaseTrieMutPatch) -> H256 {
        for (key, value) in change.adds {
            self.database.set(key, Some(&value));
            self.counter.increase(key);
        }

        for key in change.removes {
            let r = self.counter.decrease(key);
            if r == 0 {
                self.database.set(key, None);
            }
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
        let (new_root, change) = insert(self.root, self.database, key, value);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, self.database, key);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, self.database, key).map(|v| v.into())
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
    use std::collections::{hash_map::Entry, HashMap};

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::*;
    use crate::impls::tests::{Data, K};

    impl ItemCounter for HashMap<H256, usize> {
        fn increase(&mut self, key: H256) -> usize {
            self.entry(key)
                .and_modify(|count| {
                    *count += 1;
                })
                .or_insert(1);
            println!("{} count++ is {}", key, self[&key]);
            self[&key]
        }

        fn decrease(&mut self, key: H256) -> usize {
            let count = match self.entry(key) {
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
            println!("{} count-- is {}", key, count);
            count
        }
    }

    #[test]
    fn it_internal_checks_hashmap_as_gc_counter() {
        let mut m = HashMap::<H256, usize>::new();
        let k = H256::random();
        assert_eq!(m.increase(k), 1);
        assert_eq!(m.decrease(k), 0);
        assert_eq!(m.increase(k), 1);
        assert_eq!(m.decrease(k), 0);
        assert_eq!(m.increase(k), 1);
        assert_eq!(m.increase(k), 2);
        assert_eq!(m.decrease(k), 1);
        assert_eq!(m.decrease(k), 0);
    }

    #[test]
    fn it_counts_roots_as_expected() {
        let key = b"0xcafe";
        let value = b"0xcode";
        let another_value = b"0xbabe";

        let mut collection = TrieCollection::new(HashMap::new(), HashMap::new());

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key, value);
        let patch = trie.into_patch();
        assert_eq!(collection.counter.get(&patch.root), None);
        let root = collection.apply(patch);
        assert_eq!(collection.counter.get(&root), Some(&1));

        // mark root for pass GC
        assert_eq!(collection.counter.increase(root), 2);

        let mut trie = collection.trie_for(root);
        assert_eq!(trie.get(key), Some(value.to_vec()));
        trie.insert(key, another_value);
        // TODO: uncomment when lookup respects keys in change
        // assert_eq!(trie.get(key), Some(another_value.to_vec()));
        let patch = trie.into_patch();
        assert_eq!(collection.counter.get(&patch.root), None);
        let another_root = collection.apply(patch);
        assert_eq!(collection.counter.get(&another_root), Some(&1));

        // first root is alive
        assert_eq!(collection.counter.get(&root), Some(&1));
        assert_eq!(collection.trie_for(root).get(key), Some(value.to_vec()));
        assert_eq!(
            collection.trie_for(another_root).get(key),
            Some(another_value.to_vec())
        );

        assert_eq!(collection.counter.decrease(root), 0);
        assert_eq!(
            collection.trie_for(another_root).get(key),
            Some(another_value.to_vec())
        );
    }

    #[quickcheck]
    fn qc_handles_several_roots_via_gc(
        kvs_1: HashMap<K, Data>,
        kvs_2: HashMap<K, Data>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }
        let mut collection = TrieCollection::new(HashMap::new(), HashMap::new());

        let mut root = crate::empty_trie_hash();
        let mut roots = vec![];

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());

            let patch = trie.into_patch();
            root = collection.apply(patch);

            roots.push(root);
        }

        let trie = collection.trie_for(root);
        for k in kvs_1.keys() {
            assert_eq!(
                kvs_1[k],
                bincode::deserialize(&trie.get(&k.to_bytes()).unwrap()).unwrap()
            );
        }

        let snap = dbg!(root);
        // TODO: recursive increase all H256 stored entries for snap roots
        assert!(collection.counter.increase(snap) >= 1);

        // assert!(roots
        //     .into_iter()
        //     .all(|root| collection.counter.get(&root).copied().unwrap() >= 1));

        for (k, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
            let patch = trie.into_patch();
            root = collection.apply(patch);
        }

        let trie = collection.trie_for(root);
        for k in kvs_2.keys() {
            assert_eq!(
                kvs_2[k],
                bincode::deserialize(&trie.get(&k.to_bytes()).unwrap()).unwrap()
            );
        }

        // let trie = collection.trie_for(dbg!(snap));
        // for k in kvs_1.keys() {
        //     assert_eq!(
        //         kvs_1[k],
        //         bincode::deserialize(&trie.get(&k.to_bytes()).unwrap()).unwrap()
        //     );
        // }

        TestResult::passed()
    }
}
