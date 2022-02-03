#![allow(unused)] // FIXME: delete this line

use std::{borrow::Cow, collections::HashMap, cell::{UnsafeCell, RefCell}};

use dashmap::DashMap;
use primitive_types::H256;

use crate::database::{Database, DatabaseMut};

#[derive(Debug, Default)]
pub struct MemoryBackend {
    storage: DashMap<H256, Vec<u8>>
}

impl MemoryBackend {
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }
}

impl Database for MemoryBackend {
    fn get(&self, key: H256) -> &[u8] {
        self.storage
            .get(&key)
            .expect(&format!("Key {} should be present in a collection", key))
            .value()
            .as_slice()
    }
}

impl DatabaseMut for MemoryBackend {
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        self.storage
            .insert(key, value.to_vec());
    }

    fn gc_try_cleanup_node<F>(&self, key: H256, child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        todo!()
    }

    fn gc_pin_root(&self, root: H256) {
        todo!()
    }

    fn gc_unpin_root(&self, root: H256) -> bool {
        todo!()
    }

    fn gc_count(&self, key: H256) -> usize {
        todo!()
    }

    fn node_exist(&self, key: H256) -> bool {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{empty_trie_hash, trie::TrieHandle};

    use super::*;
    use hex_literal::hex;
    use std::str::FromStr;

    fn dummy_extractor(data: &[u8]) -> Vec<H256> {
        vec![]
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

        // let btrie = MemoryTrieMut::build(&map);
        let btrie = TrieHandle::<crate::trie::backends::MemoryBackend>::build(&map, |data| vec![]);

        assert_eq!(
            btrie.root(),
            H256::from_str("cb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89")
                .unwrap()
        );
        assert_eq!(
            btrie.get("key2bb".as_bytes(), dummy_extractor),
            Some("aval3".as_bytes().to_vec())
        );
        assert_eq!(btrie.get("key2bbb".as_bytes(), dummy_extractor), None);

        let mut mtrie = TrieHandle::<crate::trie::backends::MemoryBackend>::default();
        for (key, value) in &map {
            mtrie.insert(key, value, dummy_extractor);
        }

        assert_eq!(btrie.inner(), mtrie.inner());

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes(), dummy_extractor);
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(btrie.inner(), mtrie.inner());

        for key in map.keys() {
            mtrie.delete(key);
        }

        assert!(mtrie.inner().is_empty());
        assert!(mtrie.root == empty_trie_hash!());
    }

    #[test]
    fn trie_two_keys() {
        let mut mtrie = TrieHandle::<crate::trie::backends::MemoryBackend>::default();
        mtrie.insert("key1".as_bytes(), "aval1".as_bytes(), dummy_extractor);
        mtrie.insert("key2bb".as_bytes(), "aval3".as_bytes(), dummy_extractor);
        let db1 = mtrie.inner().clone();

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes(), dummy_extractor);
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(db1, mtrie.inner());
    }

    #[test]
    fn trie_multiple_prefixed_keys() {
        let key1 = &hex!("af");
        let key2 = &hex!("a2");
        let key3 = &hex!("b3");
        let keyc = &hex!("bf");
        let val = &hex!("bb");
        let mut mtrie = TrieHandle::<crate::trie::backends::MemoryBackend>::default();
        mtrie.insert(key1, val, dummy_extractor);
        mtrie.insert(key2, val, dummy_extractor);
        mtrie.insert(key3, val, dummy_extractor);
        mtrie.insert(keyc, val, dummy_extractor);
        mtrie.delete(keyc);

        assert_eq!(mtrie.get(key1, dummy_extractor).unwrap(), val);
        assert_eq!(mtrie.get(key2, dummy_extractor).unwrap(), val);
        assert_eq!(mtrie.get(key3, dummy_extractor).unwrap(), val);
    }
}
