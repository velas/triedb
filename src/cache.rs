use std::{
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
};

use primitive_types::H256;

use crate::{CachedDatabaseHandle, Database};

#[derive(Default, Debug)]
pub struct CachedHandle<D> {
    pub db: D,
    cache: Cache,
}

impl<D: Clone> Clone for CachedHandle<D> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            cache: Cache::new(),
        }
    }
}

impl<D: CachedDatabaseHandle> CachedHandle<D> {
    pub fn new(db: D) -> Self {
        Self {
            db,
            cache: Cache::new(),
        }
    }

    pub fn clear_cache(&mut self) {
        self.cache = Cache::new();
    }
}

impl<D: CachedDatabaseHandle> Database for CachedHandle<D> {
    fn get(&self, key: H256) -> &[u8] {
        if !self.cache.contains_key(key) {
            self.cache.insert(key, self.db.get(key))
        } else {
            self.cache.get(key).unwrap()
        }
    }
}

#[derive(Default, Debug)]
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

    pub fn insert(&self, key: H256, value: Vec<u8>) -> &[u8] {
        let cache = unsafe { &mut *self.cache.get() };
        let index = cache.len();
        self.map.borrow_mut().insert(key, index);
        cache.push(value);
        &cache[index]
    }

    pub fn get(&self, key: H256) -> Option<&[u8]> {
        let cache = unsafe { &mut *self.cache.get() };
        let map = self.map.borrow_mut();
        match map.get(&key) {
            Some(index) => Some(&cache[*index]),
            None => None,
        }
    }

    pub fn contains_key(&self, key: H256) -> bool {
        let map = self.map.borrow_mut();
        map.contains_key(&key)
    }
}
