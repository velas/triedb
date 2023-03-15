use std::marker::PhantomData;

use primitive_types::H256;
use sha3::{Digest, Keccak256};

/// Represents a trie that is mutable.
pub trait TrieMut {
    /// Get the root hash of the current trie.
    fn root(&self) -> H256;
    /// Insert a value to the trie.
    fn insert(&mut self, key: &[u8], value: &[u8]);
    /// Delete a value in the trie.
    fn delete(&mut self, key: &[u8]);
    /// Get a value in the trie.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// Represents a mutable trie that is operated on any RLP values.
#[derive(Clone, Default, Debug)]
pub struct AnyTrieMut<T>(T);

impl<T: TrieMut> AnyTrieMut<T> {
    /// Into the underlying TrieMut object.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_trie(self) -> T {
        self.0
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        AnyTrieMut(trie)
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K: crate::rlp::Encodable, V: crate::rlp::Encodable>(
        &mut self,
        key: &K,
        value: &V,
    ) {
        let key = crate::rlp::encode(key).to_vec();
        let value = crate::rlp::encode(value).to_vec();

        self.0.insert(&key, &value)
    }

    /// Delete a value in the trie.
    pub fn delete<K: crate::rlp::Encodable>(&mut self, key: &K) {
        let key = crate::rlp::encode(key).to_vec();

        self.0.delete(&key)
    }

    /// Get a value in the trie.
    pub fn get<K: crate::rlp::Encodable, V: for<'v> crate::rlp::Decodable<'v>>(
        &self,
        key: &K,
    ) -> Option<V> {
        let key = crate::rlp::encode(key).to_vec();
        self.0
            .get(&key)
            .map(|value| crate::rlp::decode(&value).expect("Unable to decode value"))
    }
}

/// Represents a mutable trie that is operated on a fixed RLP value type.
#[derive(Clone, Debug)]
pub struct FixedTrieMut<T, K, V>(AnyTrieMut<T>, PhantomData<(K, V)>);

impl<
        T: TrieMut + Default,
        K: crate::rlp::Encodable,
        V: crate::rlp::Encodable + for<'r> crate::rlp::Decodable<'r>,
    > Default for FixedTrieMut<T, K, V>
{
    fn default() -> Self {
        FixedTrieMut::new(T::default())
    }
}

impl<
        T: TrieMut,
        K: crate::rlp::Encodable,
        V: crate::rlp::Encodable + for<'r> crate::rlp::Decodable<'r>,
    > FixedTrieMut<T, K, V>
{
    /// Into the underlying TrieMut object.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        FixedTrieMut(AnyTrieMut::new(trie), PhantomData)
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert(&mut self, key: &K, value: &V) {
        self.0.insert(key, value)
    }

    /// Delete a value in the trie.
    pub fn delete(&mut self, key: &K) {
        self.0.delete(key)
    }

    /// Get a value in the trie.
    pub fn get(&self, key: &K) -> Option<V> {
        self.0.get(key)
    }
}

/// Represents a secure mutable trie where the key is hashed.
#[derive(Clone, Debug)]
pub struct SecureTrieMut<T>(T);

impl<T: TrieMut + Default> Default for SecureTrieMut<T> {
    fn default() -> Self {
        SecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> SecureTrieMut<T> {
    /// Into the underlying TrieMut object.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_trie(self) -> T {
        self.0
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        SecureTrieMut(trie)
    }

    fn secure_key<K: AsRef<[u8]>>(key: &K) -> Vec<u8> {
        Keccak256::digest(key.as_ref()).as_slice().into()
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K: AsRef<[u8]>>(&mut self, key: &K, value: &[u8]) {
        self.0.insert(&Self::secure_key(key), value)
    }

    /// Delete a value in the trie.
    pub fn delete<K: AsRef<[u8]>>(&mut self, key: &K) {
        self.0.delete(&Self::secure_key(key))
    }

    /// Get a value in the trie.
    pub fn get<K: AsRef<[u8]>>(&self, key: &K) -> Option<Vec<u8>> {
        self.0.get(&Self::secure_key(key))
    }
}

/// Represents a secure mutable trie where the key is hashed, and
/// operated on any RLP values.
#[derive(Clone, Debug)]
pub struct AnySecureTrieMut<T>(SecureTrieMut<T>);

impl<T: TrieMut + Default> Default for AnySecureTrieMut<T> {
    fn default() -> Self {
        AnySecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> AnySecureTrieMut<T> {
    /// Into the underlying TrieMut object.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        AnySecureTrieMut(SecureTrieMut::new(trie))
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K: AsRef<[u8]>, V: crate::rlp::Encodable>(&mut self, key: &K, value: &V) {
        self.0.insert(&key, &crate::rlp::encode(value))
    }

    /// Delete a value in the trie.
    pub fn delete<K: AsRef<[u8]>>(&mut self, key: &K) {
        self.0.delete(&key)
    }

    /// Get a value in the trie.
    pub fn get<K: AsRef<[u8]>, V: for<'v> crate::rlp::Decodable<'v>>(&self, key: &K) -> Option<V> {
        self.0
            .get(&key)
            .map(|value| crate::rlp::decode(&value).expect("Unable to decode value"))
    }
}

/// Represents a secure mutable trie where the key is hashed, and
/// operated on a fixed RLP value type.
#[derive(Clone, Debug)]
pub struct FixedSecureTrieMut<T, K, V>(AnySecureTrieMut<T>, PhantomData<(K, V)>);

impl<
        T: TrieMut + Default,
        K: AsRef<[u8]>,
        V: crate::rlp::Encodable + for<'r> crate::rlp::Decodable<'r>,
    > Default for FixedSecureTrieMut<T, K, V>
{
    fn default() -> Self {
        FixedSecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut, K: AsRef<[u8]>, V: crate::rlp::Encodable + for<'r> crate::rlp::Decodable<'r>>
    FixedSecureTrieMut<T, K, V>
{
    /// Into the underlying TrieMut object.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        FixedSecureTrieMut(AnySecureTrieMut::new(trie), PhantomData)
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert(&mut self, key: &K, value: &V) {
        self.0.insert(key, value)
    }

    /// Delete a value in the trie.
    pub fn delete(&mut self, key: &K) {
        self.0.delete(key)
    }

    /// Get a value in the trie.
    pub fn get(&self, key: &K) -> Option<V> {
        self.0.get(key)
    }
}
