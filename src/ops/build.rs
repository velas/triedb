use crate::database::*;
use std::collections::HashMap;

use crate::merkle::{
    empty_nodes,
    nibble::{self, Nibble, NibbleVec},
    MerkleNode, MerkleValue,
};
use crate::Result;

use super::BasicOps;

fn make_submap<'a, 'b: 'a, T: Iterator<Item = (&'a NibbleVec, &'a &'b [u8])>>(
    common_len: usize,
    map: T,
) -> HashMap<NibbleVec, &'b [u8]> {
    let mut submap = HashMap::new();
    for (key, &value) in map {
        submap.insert(key[common_len..].into(), value);
    }
    submap
}

trait BuildExt: DatabaseMut + BasicOps {
    fn build_value<'a>(&mut self, node: MerkleNode<'a>) -> Result<MerkleValue<'a>> {
        let value = self.add_value(node)?;

        Ok(value)
    }

    // Build tree from Map inserting all needed elements into database.
    // Returns root node element.
    fn build_tree<'a>(
        &mut self,
        map: &HashMap<NibbleVec, &'a [u8]>,
    ) -> Result<Hashed<MerkleNode<'a>>> {
        assert!(!map.is_empty());
        if map.len() == 1 {
            let (key, value) = map.iter().next().unwrap();
            return Ok(MerkleNode::Leaf(key.clone(), *value).into());
        }

        debug_assert!(map.len() > 1);
        let common = nibble::common_all(map.keys().map(|v| v.as_ref()));

        let root = if !common.is_empty() {
            let submap = make_submap(common.len(), map.iter());
            debug_assert!(!submap.is_empty());

            let node = self.build_tree(&submap)?;

            let value = self.build_value(node.into_inner())?;

            MerkleNode::Extension(common.into(), value)
        } else {
            let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

            for (i, node) in nodes.iter_mut().enumerate() {
                let nibble = Nibble::from(i);

                let submap = make_submap(
                    1,
                    map.iter()
                        .filter(|&(key, _value)| !key.is_empty() && key[0] == nibble),
                );

                if !submap.is_empty() {
                    let sub_node = self.build_tree(&submap)?;

                    let value = self.build_value(sub_node.into_inner())?;

                    *node = value;
                }
            }

            let additional = map
                .iter()
                .find(|&(key, _value)| key.is_empty())
                .map(|(_key, value)| *value);

            MerkleNode::Branch(nodes, additional)
        };
        let mut hashed = root.into();
        self.insert_node(&mut hashed)?;
        Ok(hashed)
    }
}

impl<T> BuildExt for T where T: DatabaseMut + BasicOps {}
