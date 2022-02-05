#![allow(dead_code)] // FIXME: delete this lint

pub mod backends;
pub mod typed;

use std::collections::HashMap;

use super::H256;
use crate::database::DatabaseMut;
use crate::empty_trie_hash;

pub struct TrieHandle<D> {
    database: D,
    root: H256,
}

impl<D: Default> Default for TrieHandle<D> {
    fn default() -> Self {
        Self {
            database: Default::default(),
            root: empty_trie_hash!(),
        }
    }
}

impl<D> TrieHandle<D> {
    pub fn new(database: D, root: H256) -> Self {
        Self { database, root }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn database(&self) -> &D {
        &self.database
    }
}

impl<D: DatabaseMut> TrieHandle<D> {
    pub fn insert<F: FnMut(&[u8]) -> Vec<H256> + Clone>(
        &mut self,
        key: &[u8],
        value: &[u8],
        child_extractor: F,
    ) {
        self.root = crate::insert(&self.database, self.root, key, value, child_extractor);
    }

    pub fn delete<F: FnMut(&[u8]) -> Vec<H256> + Clone>(&mut self, key: &[u8], child_extractor: F) {
        self.root = crate::delete(self.root, &self.database, key, child_extractor);
    }

    pub fn get<F>(&self, key: &[u8], _child_extractor: F) -> Option<Vec<u8>> {
        //F не нужен
        crate::get(&self.database, self.root, key).map(|v| v.into())
    }

    pub fn build<F: FnMut(&[u8]) -> Vec<H256> + Clone>(
        map: &HashMap<Vec<u8>, Vec<u8>>,
        child_extractor: F,
    ) -> Self
    where
        Self: Default,
    {
        let mut ret = Self::default();
        let new_root = crate::build(&ret.database, map, child_extractor);
        ret.root = new_root;
        ret
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    trait ChildExtractor {
        fn deserialize(&mut self, data: &[u8]) -> Vec<H256>; // TODO: SmallVec instead Vec<_>
    }

    impl<F> ChildExtractor for F
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        fn deserialize(&mut self, data: &[u8]) -> Vec<H256> {
            (*self)(data)
        }
    }

    #[test]
    fn child_extractor_as_trait() {
        fn foo<F: ChildExtractor>(bar: &[u8], mut child_extractor: F) -> Vec<H256> {
            child_extractor.deserialize(bar)
        }

        // CHILD EXTRACTOR AS A CLOSURE
        // type annotations for closure are mandatory
        let ret = foo(&[0, 1], |_data: &[u8]| vec![H256([11; 32]), H256([22; 32])]);

        assert_eq!(ret, vec![H256([11; 32]), H256([22; 32])]);

        // CHILD EXTRACTOR AS A FUNCTION POINTER
        fn static_deserializer(_data: &[u8]) -> Vec<H256> {
            vec![H256([77; 32]), H256([66; 32])]
        }

        let ret = foo(&[0, 1], static_deserializer);

        assert_eq!(ret, vec![H256([77; 32]), H256([66; 32])]);
    }
}
