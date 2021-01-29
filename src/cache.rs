use std::cell::{RefCell, UnsafeCell};
use std::collections::HashMap;

use super::merkle::MerkleNode;
use primitive_types::H256;
use rlp::Rlp;

pub struct Cache {
    cache: UnsafeCell<Vec<Vec<u8>>>,
    map: RefCell<HashMap<H256, usize>>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            cache: UnsafeCell::new(Vec::new()),
            map: RefCell::new(HashMap::new()),
        }
    }

    pub fn insert<'a>(&'a self, key: H256, value: Vec<u8>) -> &'a [u8] {
        let cache = unsafe { &mut *self.cache.get() };
        let index = cache.len();
        self.map.borrow_mut().insert(key, index);
        cache.push(value);
        &cache[index]
    }

    pub fn get<'a>(&'a self, key: H256) -> Option<&'a [u8]> {
        let cache = unsafe { &mut *self.cache.get() };
        let mut map = self.map.borrow_mut();
        match map.get(&key) {
            Some(index) => Some(&cache[*index]),
            None => None,
        }
    }

    pub fn contains_key(&self, key: H256) -> bool {
        let mut map = self.map.borrow_mut();
        map.contains_key(&key)
    }
}
