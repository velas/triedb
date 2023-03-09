use super::NibblePair;
use crate::merkle::{empty_nodes, Branch, Extension, Leaf, MerkleNode, MerkleValue};
use crate::nibble::{NibbleType, NibbleVec};

use bytes::Buf;
pub use fastrlp::{Decodable, DecodeError};
use primitive_types::H256;

pub fn decode<'a, T: Decodable<'a>>(mut val: &'a [u8]) -> Result<T, DecodeError> {
    Decodable::decode(&mut val)
}

impl<'a> MerkleNode<'a> {
    pub fn fast_decode_with_header(
        buf: &mut &'a [u8],
        h: fastrlp::Header,
    ) -> Result<MerkleNode<'a>, fastrlp::DecodeError> {
        if !h.list {
            return Err(fastrlp::DecodeError::UnexpectedString);
        }

        let node = if is_list_consume_rlp(
            &buf[..h.payload_length],
            2, // len
        ) {
            // check if rlp_list.len() == 2 (leaf or extension)
            let NibblePair(nibbles, typ) = fastrlp::Decodable::decode(buf)?;
            match typ {
                NibbleType::Leaf => MerkleNode::Leaf(Leaf {
                    nibbles,
                    data: fastrlp::Decodable::decode(buf)?,
                }),
                NibbleType::Extension => MerkleNode::Extension(Extension {
                    nibbles,
                    value: fastrlp::Decodable::decode(buf)?,
                }),
            }
        } else {
            let mut nodes: [MerkleValue; 16] = empty_nodes();
            for (_i, node) in nodes.iter_mut().enumerate() {
                *node = fastrlp::Decodable::decode(buf)?;
            }
            let val: &[u8] = fastrlp::Decodable::decode(buf)?;
            let value = if val.is_empty() { None } else { Some(val) };
            MerkleNode::Branch(Branch {
                childs: nodes,
                data: value,
            })
        };
        Ok(node)
    }

    /// Whether the node can be inlined to a merkle value.
    pub fn inlinable(&self) -> bool {
        <Self as fastrlp::Encodable>::length(self) < 32
    }
}

impl<'de> fastrlp::Decodable<'de> for MerkleNode<'de> {
    fn decode(buf: &mut &'de [u8]) -> Result<MerkleNode<'de>, fastrlp::DecodeError> {
        let h = fastrlp::Header::decode(buf)?;

        Self::fast_decode_with_header(buf, h)
    }
}

impl<'de> fastrlp::Decodable<'de> for MerkleValue<'de> {
    fn decode(buf: &mut &'de [u8]) -> Result<Self, fastrlp::DecodeError> {
        let h = fastrlp::Header::decode(buf)?;

        if !h.list {
            if h.payload_length == 0 {
                return Ok(MerkleValue::Empty);
            }

            // TODO: Add posibility to make inline decoding.
            if h.payload_length == 32 {
                let to = H256::from_slice(&buf[..32]);
                buf.advance(32);
                return Ok(MerkleValue::Hash(to));
            }
        } else if h.payload_length < 32 {
            let node: MerkleNode<'de> = MerkleNode::fast_decode_with_header(buf, h)?;
            return Ok(MerkleValue::Full(Box::new(node)));
        }

        Err(fastrlp::DecodeError::Custom(
            "Not valid combination of payload_slize and list flag for MerkleValue, header",
        ))
    }
}

// Check if this rlp list consume all buffer, with given number of items.
pub(crate) fn is_list_consume_rlp(mut buf: &[u8], num: usize) -> bool {
    let buf = &mut buf;
    for _i in 0..num {
        let h = if let Ok(h) = fastrlp::Header::decode(buf) {
            h
        } else {
            return false;
        };
        if h.payload_length > buf.len() {
            return false;
        }
        buf.advance(h.payload_length);
    }
    buf.is_empty()
}

impl<'de> fastrlp::Decodable<'de> for NibblePair {
    fn decode(buf: &mut &'de [u8]) -> Result<NibblePair, fastrlp::DecodeError> {
        let h = fastrlp::Header::decode(buf)?;
        if h.list {
            return Err(fastrlp::DecodeError::UnexpectedList);
        }

        let data = &buf[..h.payload_length];
        buf.advance(h.payload_length);

        let start_odd = data[0] & 0b00010000 == 0b00010000;
        let is_leaf = data[0] & 0b00100000 == 0b00100000;

        let start_index = if start_odd { 1 } else { 2 };

        let len = data.len() * 2;

        let mut vec = NibbleVec::with_capacity(len);

        for i in start_index..len {
            if i & 1 == 0 {
                // even
                vec.push(((data[i / 2] & 0xf0) >> 4).into());
            } else {
                vec.push((data[i / 2] & 0x0f).into());
            }
        }

        Ok(NibblePair(
            vec,
            if is_leaf {
                NibbleType::Leaf
            } else {
                NibbleType::Extension
            },
        ))
    }
}
