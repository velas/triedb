use primitive_types::H256;

use super::nibble::NibbleVec;

/// Represents a merkle node.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum MerkleNode<'a> {
    Leaf(Leaf<'a>),
    Extension(Extension<'a>),
    Branch(Branch<'a>),
}

impl<'a> MerkleNode<'a> {
    pub fn branch(childs: [MerkleValue<'a>; 16], data: Option<&'a [u8]>) -> Self {
        Self::Branch(Branch { childs, data })
    }

    pub fn leaf(nibbles: NibbleVec, data: &'a [u8]) -> Self {
        Self::Leaf(Leaf { nibbles, data })
    }

    pub fn extension(nibbles: NibbleVec, value: MerkleValue<'a>) -> Self {
        Self::Extension(Extension { nibbles, value })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf<'a> {
    pub nibbles: NibbleVec,
    pub data: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    pub nibbles: NibbleVec,
    pub value: MerkleValue<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch<'a> {
    pub childs: [MerkleValue<'a>; 16],
    pub data: Option<&'a [u8]>,
}

impl<'a> MerkleNode<'a> {
    /// Return nibbles that was inlined to this node.
    /// This nibble represent a suffix between parent node, and child node/value.
    //TODO: Return nible slice
    pub fn nibbles(&self) -> Option<NibbleVec> {
        Some(match self {
            Self::Branch(..) => return None,
            Self::Leaf(Leaf { nibbles, .. }) => nibbles.clone(),
            Self::Extension(Extension { nibbles, .. }) => nibbles.clone(),
        })
    }

    // Return data, if current node can have it
    pub fn data(&self) -> Option<&[u8]> {
        match *self {
            Self::Branch(Branch { data, .. }) => data,
            Self::Leaf(Leaf { data, .. }) => Some(data),
            Self::Extension(..) => unreachable!("Data on extension is not possible by design"),
        }
    }

    pub fn filter_extension(&self) -> Option<&Self> {
        match *self {
            Self::Extension(..) => None,
            _ => Some(self),
        }
    }
}

/// Represents a merkle value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleValue<'a> {
    Empty,
    Full(Box<MerkleNode<'a>>),
    Hash(H256),
}

pub const fn empty_nodes() -> [MerkleValue<'static>; 16] {
    [
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
        MerkleValue::Empty,
    ]
}
