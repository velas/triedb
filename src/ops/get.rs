use rlp::{self, Rlp};

use crate::{
    database::Database,
    merkle::{nibble::NibbleVec, MerkleNode, MerkleValue},
};

trait GetExt: Database {
    fn get_by_value<'a>(&'a self, merkle: MerkleValue<'a>, nibble: NibbleVec) -> Option<&'a [u8]> {
        match merkle {
            MerkleValue::Empty => None,
            MerkleValue::Full(subnode) => self.get_by_node(subnode.as_ref().clone(), nibble),
            MerkleValue::Hash(h) => {
                let subnode = self.get_node(h);
                self.get_by_node(subnode.into_inner(), nibble)
            }
        }
    }

    fn get_by_node<'a>(&'a self, node: MerkleNode<'a>, nibble: NibbleVec) -> Option<&'a [u8]> {
        match node {
            MerkleNode::Leaf(node_nibble, node_value) => {
                if node_nibble == nibble {
                    Some(node_value)
                } else {
                    None
                }
            }
            MerkleNode::Extension(node_nibble, node_value) => {
                if nibble.starts_with(&node_nibble) {
                    self.get_by_value(node_value, nibble[node_nibble.len()..].into())
                } else {
                    None
                }
            }
            MerkleNode::Branch(node_nodes, node_additional) => {
                if nibble.is_empty() {
                    node_additional
                } else {
                    let ni: usize = nibble[0].into();
                    self.get_by_value(node_nodes[ni].clone(), nibble[1..].into())
                }
            }
        }
    }
}
