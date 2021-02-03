use primitive_types::H256;

use crate::{delete, get, insert, Change, DatabaseHandle, TrieMut};

pub trait ItemCounter {
    fn increase(&mut self, key: H256) -> usize;
    fn decrease(&mut self, key: H256) -> usize;
}

pub trait DatabaseMut {
    fn get(&self, key: H256) -> &[u8];
    fn set(&mut self, key: H256, value: Option<&[u8]>);
}

impl<'a, D: DatabaseMut> DatabaseHandle for &'a D {
    fn get(&self, key: H256) -> &[u8] {
        DatabaseMut::get(*self, key)
    }
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

    pub fn apply<'a>(&'a mut self, trie: DatabaseTrieMut<'a, D>) {
        for (key, value) in trie.change.adds {
            self.database.set(key, Some(&value));
            self.counter.increase(key);
        }

        for key in trie.change.removes {
            let r = self.counter.decrease(key);
            if r == 0 {
                self.database.set(key, None);
            }
        }
    }
}

pub struct DatabaseTrieMut<'a, D: DatabaseMut + 'a> {
    database: &'a D,
    change: Change,
    root: H256,
}

impl<'a, D: DatabaseMut> TrieMut for DatabaseTrieMut<'a, D> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, &self.database, key, value);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, &self.database, key);

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &self.database, key).map(|v| v.into())
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
            let count = self.entry(key).or_insert(0);
            *count += 1;
            *count
        }

        fn decrease(&mut self, key: H256) -> usize {
            match self.entry(key) {
                Entry::Vacant(_) => 0,
                Entry::Occupied(entry) if *entry.get() <= 1 => {
                    entry.remove();
                    0
                }
                Entry::Occupied(mut entry) => {
                    *entry.get_mut() -= 1;
                    *entry.get()
                }
            }
        }
    }

    #[test]
    fn it_internal_checks_hashmap_as_gc_counter() {
        let mut m = HashMap::<H256, usize>::new();
        let k = H256::random();
        assert_eq!(m.decrease(k), 0);
        assert_eq!(m.increase(k), 1);
        assert_eq!(m.decrease(k), 0);
        assert_eq!(m.increase(k), 1);
        assert_eq!(m.increase(k), 2);
        assert_eq!(m.decrease(k), 1);
        assert_eq!(m.decrease(k), 0);
    }

    #[quickcheck]
    fn it_handles_several_roots_via_gc(kvs_1: HashMap<K, Data>, kvs_2: HashMap<K, Data>) {
        let mut collection = TrieCollection::new(HashMap::new(), HashMap::new());

        let mut trie_1 = collection.trie_for(crate::empty_trie_hash());
        for (k, data) in kvs_1.iter() {
            trie_1.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
        }
        // reads before apply
        for k in kvs_1.keys() {
            assert_eq!(
                kvs_1[k],
                bincode::deserialize(&trie_1.get(&k.to_bytes()).unwrap()).unwrap()
            );
        }
    }
}
