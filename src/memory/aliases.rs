use crate::{
    AnySecureTrieMut, AnyTrieMut, 
    FixedSecureTrieMut, FixedTrieMut, SecureTrieMut,
};
use super::trie_mut::MemoryTrieMut;

/// A memory-backed trie where the value is operated on a fixed RLP
/// value type.
pub type FixedMemoryTrieMut<K, V> = FixedTrieMut<MemoryTrieMut, K, V>;
/// A memory-backed trie where the key is hashed and the value is
/// operated on a fixed RLP value type.
pub type FixedSecureMemoryTrieMut<K, V> = FixedSecureTrieMut<MemoryTrieMut, K, V>;
/// A memory-backed trie where the key is hashed.
pub type SecureMemoryTrieMut = SecureTrieMut<MemoryTrieMut>;
/// A memory-backed trie where the value is operated on any RLP
/// values.
pub type AnyMemoryTrieMut = AnyTrieMut<MemoryTrieMut>;
/// A memory-backed trie where the key is hashed and the value is
/// operated on any RLP values.
pub type AnySecureMemoryTrieMut = AnySecureTrieMut<MemoryTrieMut>;
