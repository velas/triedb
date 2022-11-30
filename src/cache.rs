use std::{
    borrow::Borrow,
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    sync::RwLock,
};

use primitive_types::H256;

use crate::{CachedDatabaseHandle, Database};

// Single threaded cache implementation

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

// Multithreaded cache implementation

#[derive(Default, Debug)]
pub struct AsyncCachedHandle<D> {
    pub db: D,
    cache: AsyncCache,
}

impl<D> AsyncCachedHandle<D> {
    pub fn new(db: D) -> Self {
        AsyncCachedHandle {
            db,
            cache: AsyncCache::default(),
        }
    }
}

#[derive(Default, Debug)]
pub struct AsyncCachedDatabaseHandle<D> {
    db: D,
}

impl<D: Borrow<rocksdb_lib::OptimisticTransactionDB>> AsyncCachedDatabaseHandle<D> {
    pub fn new(db: D) -> Self {
        AsyncCachedDatabaseHandle { db }
    }
}

// Same implementation as for RocksDatabaseHandle<'a, D>
impl<D: Borrow<rocksdb_lib::OptimisticTransactionDB>> CachedDatabaseHandle
    for AsyncCachedDatabaseHandle<D>
{
    fn get(&self, key: H256) -> Vec<u8> {
        self.db
            .borrow()
            .get(key.as_ref())
            .expect("Error on reading database")
            .unwrap_or_else(|| panic!("Value for {} not found in database", key))
    }
}

#[derive(Default, Debug)]
struct AsyncCache {
    cache: UnsafeCell<Vec<Vec<u8>>>,
    map: RwLock<HashMap<H256, usize>>,
}

unsafe impl Sync for AsyncCache {}
unsafe impl Send for AsyncCache {}

impl AsyncCache {
    pub fn insert(&self, key: H256, value: Vec<u8>) -> &[u8] {
        let mut map = self.map.write().unwrap();
        let cache = unsafe { &mut *self.cache.get() };
        let index = cache.len();
        map.insert(key, index);
        cache.push(value);
        &cache[index]
    }

    pub fn get(&self, key: H256) -> Option<&[u8]> {
        let cache = unsafe { &mut *self.cache.get() };
        let map = self.map.read().unwrap();
        match map.get(&key) {
            Some(index) => Some(&cache[*index]),
            None => None,
        }
    }

    pub fn contains_key(&self, key: H256) -> bool {
        let map = self.map.read().unwrap();
        map.contains_key(&key)
    }
}

impl<D: CachedDatabaseHandle> Database for AsyncCachedHandle<D> {
    fn get(&self, key: H256) -> &[u8] {
        if !self.cache.contains_key(key) {
            self.cache.insert(key, self.db.get(key))
        } else {
            self.cache.get(key).unwrap()
        }
    }
}
