use primitive_types::H256;
use rlp::Encodable;
use sha3::{Digest, Keccak256};

use crate::merkle::MerkleNode;
use crate::Result;

pub type Data<'a> = &'a [u8];

// Types for lazy hash computation
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hashed<V> {
    Computed {
        hash: H256,
        value: V,
        bytes: Vec<u8>,
    },
    Plain(V),
}

impl<V> From<V> for Hashed<V> {
    fn from(v: V) -> Self {
        Self::Plain(v)
    }
}

impl<V> Hashed<V> {
    pub fn into_inner(self) -> V {
        match self {
            Hashed::Plain(v) => v,
            Hashed::Computed { value, .. } => value,
        }
    }
}

impl<V: Encodable> Hashed<V> {
    fn compute(&mut self) {
        let mut uninit = std::mem::MaybeUninit::uninit();
        unsafe {
            std::mem::swap(self, uninit.assume_init_mut());
            let mut new_self = std::mem::MaybeUninit::new(match uninit.assume_init() {
                Hashed::Plain(v) => {
                    let bytes = rlp::encode(&v).to_vec();
                    let hash = H256::from_slice(Keccak256::digest(&bytes).as_slice());
                    Hashed::Computed {
                        value: v,
                        hash,
                        bytes,
                    }
                }
                s @ Hashed::Computed { .. } => s,
            });

            std::mem::swap(self, new_self.assume_init_mut())
        };
    }
    pub fn get_computed_hash(&mut self) -> &H256 {
        self.compute();
        match self {
            Hashed::Computed { hash, .. } => &*hash,
            Hashed::Plain(_) => unreachable!(),
        }
    }

    pub fn get_computed_bytes(&mut self) -> &[u8] {
        self.compute();
        match self {
            Hashed::Computed { bytes, .. } => &*bytes,
            Hashed::Plain(_) => unreachable!(),
        }
    }

    pub fn try_get_hash(&self) -> Option<&H256> {
        match self {
            Hashed::Computed { hash, .. } => Some(hash),
            Hashed::Plain(_) => None,
        }
    }

    pub fn try_get_bytes(&self) -> Option<&[u8]> {
        match self {
            Hashed::Computed { bytes, .. } => Some(bytes),
            Hashed::Plain(_) => None,
        }
    }

    pub fn get_data(&self) -> &V {
        match self {
            Hashed::Computed { value, .. } => value,
            Hashed::Plain(value) => value,
        }
    }
}

/// An immutable database handle.
/// This database is optimized for handling MerkleNode.
/// It store MerkleNode by it's Hash.
pub trait Database {
    /// Get a raw value from the database.
    fn get_node(&self, key: H256) -> Hashed<MerkleNode>;
}

/// A mutable reference to database.
///
/// A database usage has following idea behind:
/// Any get failure - can be caused by corrupted database/disk or any other kind of storage,
/// and should be handled in place - in form of panic. This is unrecoverable error.
///
/// Any write to database failures can be caused by corrupted database -
/// which is unrecoverable error, but also can be caused by "disk full"
/// or other kind of recoverable errors, end user should decide how to handle this error.
///
pub trait DatabaseMut {
    // Notify database that node should be added.
    fn insert_node(&mut self, node: &mut Hashed<MerkleNode>) -> Result<()>;
    // Notify database that node should be removed
    fn remove_node(&mut self, key: H256) -> Result<()>;
}

/// todo tests:
/// 1. Hashed get bytes.
/// 2. hashed get value.
/// 3. some quickcheck.
#[cfg(test)]
mod test {}
