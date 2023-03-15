use rlp_old as rlp;

use rlp::Decodable as DecodableOwned;
use rlp::Prototype;
use rlp::Rlp;

use super::NibblePair;
use crate::merkle::empty_nodes;
use crate::merkle::nibble::{NibbleType, NibbleVec};
use crate::merkle::MerkleNode;
use crate::merkle::MerkleValue;

pub use rlp::DecoderError;
pub type Result<T, E = DecoderError> = std::result::Result<T, E>;

pub trait Decodable<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Self>;
}

#[allow(unused)] // really used in tests
pub fn decode<'a, T: Decodable<'a> + 'a>(bytes: &'a [u8]) -> Result<T> {
    T::decode(bytes)
}

impl<'a, T> Decodable<'a> for T
where
    T: DecodableOwned,
{
    fn decode(rlp: &'a [u8]) -> Result<Self> {
        <T as DecodableOwned>::decode(&Rlp::new(rlp))
    }
}

impl Decodable<'_> for NibblePair {
    /// Decode a nibble from RLP bytes
    fn decode(bytes: &[u8]) -> Result<Self> {
        {
            let rlp = Rlp::new(bytes);
            let mut vec = NibbleVec::new();

            let data = rlp.data()?;
            let start_odd = data[0] & 0b00010000 == 0b00010000;
            let start_index = if start_odd { 1 } else { 2 };
            let is_leaf = data[0] & 0b00100000 == 0b00100000;

            let len = data.len() * 2;

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
}

impl<'a> Decodable<'a> for MerkleNode<'a> {
    /// Given a RLP, decode it to a merkle node.
    fn decode(bytes: &'a [u8]) -> Result<Self> {
        let rlp = Rlp::new(bytes);
        let node = match rlp.prototype()? {
            Prototype::List(2) => {
                let NibblePair(nibbles, typ) = NibblePair::decode(rlp.at(0)?.as_raw())?;
                match typ {
                    NibbleType::Leaf => MerkleNode::leaf(nibbles, rlp.at(1)?.data()?),
                    NibbleType::Extension => {
                        MerkleNode::extension(nibbles, MerkleValue::decode(rlp.at(1)?.as_raw())?)
                    }
                }
            }
            Prototype::List(17) => {
                let mut nodes: [MerkleValue; 16] = empty_nodes();
                for (i, node) in nodes.iter_mut().enumerate() {
                    *node = MerkleValue::decode(rlp.at(i)?.as_raw())?;
                }
                let value = if rlp.at(16)?.is_empty() {
                    None
                } else {
                    Some(rlp.at(16)?.data()?)
                };
                MerkleNode::branch(nodes, value)
            }
            _ => panic!(),
        };
        Ok(node)
    }
}

impl<'a> Decodable<'a> for MerkleValue<'a> {
    /// Given a RLP, decode it to a merkle value.
    fn decode(bytes: &'a [u8]) -> Result<Self> {
        let rlp = Rlp::new(bytes);
        if rlp.is_empty() {
            return Ok(MerkleValue::Empty);
        }

        if rlp.size() == 32 {
            return Ok(MerkleValue::Hash(rlp.as_val()?));
        }

        if rlp.size() < 32 {
            return Ok(MerkleValue::Full(Box::new(MerkleNode::decode(
                rlp.as_raw(),
            )?)));
        }

        panic!(); // TODO: convert into Err(Error)
    }
}
