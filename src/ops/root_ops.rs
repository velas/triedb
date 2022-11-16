use std::collections::HashMap;

use primitive_types::H256;

use super::{
    insert as insert_mod, delete as delete_mod, build as build_mod, get as get_mod,
};
use crate::merkle::{nibble, MerkleNode};
use crate::{empty_trie_hash, Change, Database};
use rlp::Rlp;
use sha3::{Digest, Keccak256};

/// Insert to a merkle trie. Return the new root hash and the changes.
pub fn insert<D: Database>(
    root: H256,
    database: &D,
    key: &[u8],
    value: &[u8],
) -> (H256, Change) {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = if root == empty_trie_hash!() {
        insert_mod::insert_by_empty(nibble, value)
    } else {
        let old = MerkleNode::decode(&Rlp::new(database.get(root)))
            .expect("Unable to decode Node value");
        change.remove_raw(root);
        insert_mod::insert_by_node(old, nibble, value, database)
    };
    change.merge(&subchange);
    change.add_node(&new);

    let hash =
        H256::from_slice(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
    (hash, change)
}


/// Delete a key from a markle trie. Return the new root hash and the
/// changes.
pub fn delete<D: Database>(root: H256, database: &D, key: &[u8]) -> (H256, Change) {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = if root == empty_trie_hash!() {
        return (root, change);
    } else {
        let old = MerkleNode::decode(&Rlp::new(database.get(root)))
            .expect("Unable to decode Node value");
        change.remove_raw(root);
        delete_mod::delete_by_node(old, nibble, database)
    };
    change.merge(&subchange);

    match new {
        Some(new) => {
            change.add_node(&new);

            let hash = H256::from_slice(
                Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice(),
            );
            (hash, change)
        }
        None => (empty_trie_hash!(), change),
    }
}

/// Build a merkle trie from a map. Return the root hash and the
/// changes.
pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> (H256, Change) {
    let mut change = Change::default();

    if map.is_empty() {
        return (empty_trie_hash!(), change);
    }

    let mut node_map = HashMap::new();
    for (key, value) in map {
        node_map.insert(nibble::from_key(key.as_ref()), value.as_ref());
    }

    let (node, subchange) = build_mod::build_node(&node_map);
    change.merge(&subchange);
    change.add_node(&node);

    let hash = H256::from_slice(Keccak256::digest(&rlp::encode(&node).to_vec()).as_slice());
    (hash, change)
}

/// Get a value given the root hash and the database.
pub fn get<'a, 'b, D: Database>(root: H256, database: &'a D, key: &'b [u8]) -> Option<&'a [u8]> {
    if root == empty_trie_hash!() {
        None
    } else {
        let nibble = nibble::from_key(key);
        let node =
            MerkleNode::decode(&Rlp::new(database.get(root))).expect("Unable to decode Node value");
        get_mod::get_by_node(node, nibble, database)
    }
}
