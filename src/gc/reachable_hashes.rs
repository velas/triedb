use crate::{merkle::{MerkleValue, MerkleNode}, empty_trie_hash};

use derivative::*;
use primitive_types::H256;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct ReachableHashes<F> {
    childs: Vec<H256>,
    #[derivative(Debug = "ignore")]
    child_extractor: F,
}

impl<F> ReachableHashes<F>
where
    F: FnMut(&[u8]) -> Vec<H256>,
{
    pub fn collect(merkle_node: &MerkleNode, child_extractor: F) -> Self {
        let mut this = Self {
            childs: Default::default(),
            child_extractor,
        };
        this.process_node(merkle_node);
        this
    }

    fn process_node(&mut self, merkle_node: &MerkleNode) {
        match merkle_node {
            MerkleNode::Leaf(_, d) => self.childs.extend_from_slice(&(self.child_extractor)(*d)),
            MerkleNode::Extension(_, merkle_value) => {
                self.process_value(merkle_value);
            }
            MerkleNode::Branch(merkle_values, data) => {
                if let Some(d) = data {
                    self.childs.extend_from_slice(&(self.child_extractor)(*d))
                }
                for merkle_value in merkle_values {
                    self.process_value(merkle_value);
                }
            }
        }
    }

    fn process_value(&mut self, merkle_value: &MerkleValue) {
        match merkle_value {
            MerkleValue::Empty => {}
            MerkleValue::Full(merkle_node) => self.process_node(merkle_node),
            MerkleValue::Hash(hash) => self.childs.push(*hash),
        }
    }

    pub fn childs(self) -> Vec<H256> {
        self.childs
            .into_iter()
            // Empty trie is a common default value for most
            // objects that contain submap, filtering it will reduce collissions.
            .filter(|i| *i != empty_trie_hash!())
            .collect()
    }
}
