use sha3::{Digest, Keccak256};

use super::*;
use std::{borrow::Cow, marker::PhantomData};

pub trait KeyFamily<K> {
    fn calc_key(key: &K) -> Cow<[u8]>;
}

pub struct Secure;
pub struct Raw;

pub trait ValueFamily<V> {
    fn encode_value(value: &V) -> Cow<[u8]>;
}
pub struct Encoded;

impl<K: AsRef<[u8]>> KeyFamily<K> for Secure {
    fn calc_key(key: &K) -> Cow<[u8]> {
        Cow::Owned(Keccak256::digest(key.as_ref()).as_slice().into())
    }
}
impl<K: AsRef<[u8]>> KeyFamily<K> for Raw {
    fn calc_key(key: &K) -> Cow<[u8]> {
        Cow::Borrowed(key.as_ref())
    }
}

impl<V: rlp::Encodable + rlp::Decodable> ValueFamily<V> for Encoded {
    fn encode_value(value: &V) -> Cow<[u8]> {
        Cow::Owned(rlp::encode(value).to_vec())
    }
}

impl<V: AsRef<[u8]>> ValueFamily<V> for Raw {
    fn encode_value(value: &V) -> Cow<[u8]> {
        Cow::Borrowed(value.as_ref())
    }
}

pub struct TypedTrieHandle<K, V, D> {
    _k: PhantomData<K>,
    _v: PhantomData<V>,
    handle: TrieHandle<D>,
}

impl<D: Database, KF, VF> TypedTrieHandle<KF, VF, D> {
    /// Into the underlying TrieMut object.
    pub fn inner(self) -> TrieHandle<D> {
        self.handle
    }

    /// Initialize a new mutable trie.
    pub fn new(handle: TrieHandle<D>) -> Self {
        Self {
            _k: PhantomData,
            _v: PhantomData,
            handle,
        }
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.handle.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K, V>(&mut self, key: &K, value: &V)
    where
        KF: KeyFamily<K>,
        VF: ValueFamily<V>,
    {
        self.handle
            .insert(&KF::calc_key(key), &VF::encode_value(value))
    }

    /// Delete a value in the trie.
    pub fn delete<K>(&mut self, key: &K)
    where
        KF: KeyFamily<K>,
    {
        self.handle.delete(&KF::calc_key(key))
    }

    /// Get a value in the trie.
    pub fn get<K>(&self, key: &K) -> Option<Vec<u8>>
    where
        KF: KeyFamily<K>,
    {
        self.handle.get(&KF::calc_key(key))
    }
}
