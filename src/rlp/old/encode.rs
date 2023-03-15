use rlp_old as rlp;

use rlp::RlpStream;
use std::borrow::Borrow;

use super::NibblePair;
use crate::merkle::{nibble::NibbleType, Branch, Extension, Leaf, MerkleNode, MerkleValue};

pub use rlp::encode;
pub use rlp::Encodable;

impl<'a> MerkleNode<'a> {
    /// Whether the node can be inlined to a merkle value.
    pub fn inlinable_old(&self) -> bool {
        crate::rlp::encode(self).to_vec().len() < 32
    }
}

impl rlp::Encodable for NibblePair {
    fn rlp_append(&self, s: &mut RlpStream) {
        let NibblePair(vec, typ) = self;
        let mut ret: Vec<u8> = Vec::new();

        if vec.len() & 1 == 0 {
            // even
            ret.push(0b00000000);

            for (i, val) in vec.iter().enumerate() {
                if i & 1 == 0 {
                    let v: u8 = (*val).into();
                    ret.push(v << 4);
                } else {
                    let end = ret.len() - 1;
                    let v: u8 = (*val).into();
                    ret[end] |= v;
                }
            }
        } else {
            ret.push(0b00010000);

            for (i, val) in vec.iter().enumerate() {
                if i & 1 == 0 {
                    let end = ret.len() - 1;
                    let v: u8 = (*val).into();
                    ret[end] |= v;
                } else {
                    let v: u8 = (*val).into();
                    ret.push(v << 4);
                }
            }
        }

        ret[0] |= match typ {
            NibbleType::Leaf => 0b00100000,
            NibbleType::Extension => 0b00000000,
        };

        s.append(&ret);
    }
}

impl<'a> rlp::Encodable for MerkleNode<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match *self {
            MerkleNode::Leaf(Leaf { ref nibbles, data }) => {
                s.begin_list(2);
                NibblePair::rlp_append(&NibblePair(nibbles.to_vec(), NibbleType::Leaf), s);
                data.rlp_append(s);
            }
            MerkleNode::Extension(Extension {
                ref nibbles,
                ref value,
            }) => {
                s.begin_list(2);
                NibblePair::rlp_append(&NibblePair(nibbles.to_vec(), NibbleType::Extension), s);
                value.rlp_append(s);
            }
            MerkleNode::Branch(Branch { ref childs, data }) => {
                s.begin_list(17);
                for node in childs.iter().take(16) {
                    node.rlp_append(s);
                }
                if let Some(value) = data {
                    s.append(&value);
                } else {
                    s.append_empty_data();
                };
            }
        }
    }
}

impl<'a> rlp::Encodable for MerkleValue<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match *self {
            MerkleValue::Empty => {
                s.append_empty_data();
            }
            MerkleValue::Full(ref node) => {
                debug_assert!(node.inlinable_old());
                let node: &MerkleNode = node.borrow();
                s.append(node);
            }
            MerkleValue::Hash(ref hash) => {
                s.append(hash);
            }
        }
    }
}
