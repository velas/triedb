use std::collections::VecDeque;
use primitive_types::H256;
use crate::merkle::{MerkleNode, MerkleValue};

use sha3::{Digest, Keccak256};

/// Change for a merkle trie operation.
#[derive(Default, Debug, Clone)]
pub struct Change {
    /// Additions to the database.
    pub changes: VecDeque<(H256, Option<Vec<u8>>)>,
}

impl Change {
    /// Change to add a new raw value.
    pub fn add_raw(&mut self, key: H256, value: Vec<u8>) {
        self.changes.push_back((key, Some(value)));
    }

    /// Change to add a new node.
    pub fn add_node(&mut self, node: &MerkleNode<'_>) {
        let subnode = rlp::encode(node).to_vec();
        let hash = H256::from_slice(Keccak256::digest(&subnode).as_slice());
        self.add_raw(hash, subnode);
    }

    /// Change to add a new node, and return the value added.
    pub fn add_value<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) -> MerkleValue<'b> {
        if node.inlinable() {
            MerkleValue::Full(Box::new(node.clone()))
        } else {
            let subnode = rlp::encode(node).to_vec();
            let hash = H256::from_slice(Keccak256::digest(&subnode).as_slice());
            self.add_raw(hash, subnode);
            MerkleValue::Hash(hash)
        }
    }

    /// Change to remove a raw key.
    pub fn remove_raw(&mut self, key: H256) {
        self.changes.push_back((key, None));
    }

    /// Change to remove a node. Return whether there's any node being
    /// removed.
    pub fn remove_node(&mut self, node: &MerkleNode<'_>) -> bool {
        if node.inlinable() {
            false
        } else {
            let subnode = rlp::encode(node).to_vec();
            let hash = H256::from_slice(Keccak256::digest(&subnode).as_slice());
            self.remove_raw(hash);
            true
        }
    }

    /// Merge another change to this change.
    pub fn merge(&mut self, other: &Change) {
        for (key, v) in &other.changes {
            if let Some(v) = v {
                self.add_raw(*key, v.clone());
            } else {
                self.remove_raw(*key);
            }
        }
    }

    /// Merge child tree change into this change.
    /// Changes inserts are ordered from child to root, so when we merge child subtree
    /// we should push merge it in front.
    pub fn merge_child(&mut self, other: &Change) {
        for (key, v) in other.changes.iter().rev() {
            self.changes.push_front((*key, v.clone()))
        }
    }
}
