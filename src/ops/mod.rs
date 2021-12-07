use crate::{
    database::{DatabaseMut, Hashed},
    merkle::{MerkleNode, MerkleValue},
    Result,
};

pub mod build;
// pub mod delete;
pub mod get;
// pub mod insert;

trait BasicOps: DatabaseMut {
    fn add_value<'a>(&mut self, node: MerkleNode<'a>) -> Result<MerkleValue<'a>> {
        let value = if node.inlinable() {
            MerkleValue::Full(Box::new(node.clone()))
        } else {
            let mut hashed_node: Hashed<_> = node.into();
            self.insert_node(&mut hashed_node)?;
            MerkleValue::Hash(*hashed_node.get_computed_hash())
        };
        Ok(value)
    }
}

impl<T> BasicOps for T where T: DatabaseMut {}
