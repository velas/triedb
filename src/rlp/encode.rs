use super::NibblePair;
use crate::merkle::{Branch, Extension, Leaf, MerkleNode, MerkleValue};
use crate::nibble::NibbleType;

pub use fastrlp::Encodable;

pub fn encode<V: fastrlp::Encodable>(val: &V) -> Vec<u8> {
    let mut vec_buffer = Vec::with_capacity(val.length());
    val.encode(&mut vec_buffer);
    vec_buffer
}

impl<'a> fastrlp::Encodable for MerkleNode<'a> {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            MerkleNode::Leaf(Leaf { nibbles, data }) => {
                let pair = NibblePair(nibbles.clone(), NibbleType::Leaf);
                let len = pair.length() + data.length();
                fastrlp::Header {
                    list: true,
                    payload_length: len,
                }
                .encode(out);
                pair.encode(out);
                data.encode(out);
            }
            MerkleNode::Extension(Extension { nibbles, value }) => {
                let pair = NibblePair(nibbles.clone(), NibbleType::Extension);
                let len = pair.length() + value.length();
                fastrlp::Header {
                    list: true,
                    payload_length: len,
                }
                .encode(out);
                pair.encode(out);
                value.encode(out);
            }
            MerkleNode::Branch(Branch { childs, data }) => {
                let mut len = 0;
                for node in childs.iter() {
                    len += node.length()
                }
                len += data.unwrap_or_default().length();

                fastrlp::Header {
                    list: true,
                    payload_length: len,
                }
                .encode(out);
                for node in childs.iter() {
                    node.encode(out);
                }
                data.unwrap_or_default().encode(out)
            }
        }
    }
    fn length(&self) -> usize {
        match self {
            MerkleNode::Leaf(Leaf { nibbles, data }) => {
                let pair = NibblePair(nibbles.clone(), NibbleType::Leaf);
                let len = pair.length() + data.length();
                fastrlp::Header {
                    list: true,
                    payload_length: len,
                }
                .length()
                    + len
            }
            MerkleNode::Extension(Extension { nibbles, value }) => {
                let pair = NibblePair(nibbles.clone(), NibbleType::Extension);
                let len = pair.length() + value.length();
                fastrlp::Header {
                    list: true,
                    payload_length: len,
                }
                .length()
                    + len
            }
            MerkleNode::Branch(Branch { childs, data }) => {
                let mut len = 0;
                for node in childs.iter() {
                    len += node.length()
                }

                len += data.unwrap_or_default().length();

                fastrlp::Header {
                    list: true,
                    payload_length: len,
                }
                .length()
                    + len
            }
        }
    }
}

impl<'a> fastrlp::Encodable for MerkleValue<'a> {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match *self {
            MerkleValue::Empty => fastrlp::Header {
                payload_length: 0,
                list: false,
            }
            .encode(out),
            MerkleValue::Hash(ref hash) => fastrlp::Encodable::encode(hash, out),
            MerkleValue::Full(ref node) => node.encode(out),
        }
    }
    fn length(&self) -> usize {
        match *self {
            MerkleValue::Empty => fastrlp::Header {
                payload_length: 0,
                list: false,
            }
            .length(),
            MerkleValue::Hash(_) => {
                fastrlp::Header {
                    payload_length: 32,
                    list: false,
                }
                .length()
                    + 32
            }
            MerkleValue::Full(ref node) => {
                node.length() // node include header
            }
        }
    }
}

impl fastrlp::Encodable for NibblePair {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let payload_length = self.payload_length();
        if !self.skip_rlp_header() {
            fastrlp::Header {
                payload_length,
                list: false,
            }
            .encode(out);
        }
        let typ = match self.1 {
            NibbleType::Leaf => 0b00100000,
            NibbleType::Extension => 0b00000000,
        };
        if self.0.len() % 2 == 0 {
            // even
            out.put_u8(typ);
            let mut last_u8 = 0;
            for (i, val) in self.0.iter().enumerate() {
                let v: u8 = (*val).into();
                if i % 2 == 0 {
                    last_u8 = v << 4;
                } else {
                    last_u8 |= v;
                    out.put_u8(last_u8);
                }
            }
        } else {
            let mut last_u8 = 0b00010000 | typ;

            for (i, val) in self.0.iter().enumerate() {
                let v: u8 = (*val).into();
                if i % 2 == 0 {
                    last_u8 |= v;
                    out.put_u8(last_u8)
                } else {
                    last_u8 = v << 4;
                }
            }
        }
    }
    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        if !self.skip_rlp_header() {
            return fastrlp::Header {
                payload_length,
                list: false,
            }
            .length()
                + payload_length;
        };
        payload_length
    }
}

impl NibblePair {
    // 1 byte prefix + ceil(len_in_nible / 2)
    // exampe:
    // 1 nibble  = 1 + 0
    // 2 nibbles = 1 + 1
    // 3 nibbles = 1 + 1
    // ...
    fn payload_length(&self) -> usize {
        1 + self.0.len() / 2
    }
    // If we have zero or one nible, it's byte representation would be less < EMPTY_STRING_CODE(0x80), and be serialized as single byte without length prefix
    fn skip_rlp_header(&self) -> bool {
        self.payload_length() == 1
    }
}
