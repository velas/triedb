use std::collections::HashMap;

use primitive_types::H256;

use crate::{
    database::DatabaseMut,
    merkle::{
        empty_nodes,
        nibble::{self, Nibble, NibbleVec},
        MerkleNode, MerkleValue,
    },
};

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

// FIXME: remove proxy function
pub fn build_value<'a, D, F>(
    database: &'a D,
    node: MerkleNode<'a>,
    child_extractor: F,
) -> MerkleValue<'a>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    crate::add_value(database, &node, child_extractor)
}

pub fn build_node<'a, D, F>(
    database: &'a D,
    map: &HashMap<NibbleVec, &'a [u8]>,
    child_extractor: F,
) -> MerkleNode<'a>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    assert!(!map.is_empty());
    if map.len() == 1 {
        let key = map.keys().next().unwrap();
        return MerkleNode::Leaf(key.clone(), map.get(key).unwrap());
    }

    debug_assert!(map.len() > 1);
    let common = nibble::common_all(map.keys().map(|v| v.as_ref()));

    if !common.is_empty() {
        let submap = make_submap(common.len(), map.iter());
        debug_assert!(!submap.is_empty());

        let node = build_node(database, &submap, child_extractor.clone());

        let value = build_value(database, node, child_extractor);

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
                let sub_node = build_node(database, &submap, child_extractor.clone());

                let value = build_value(database, sub_node, child_extractor.clone());

                *node = value;
            }
        }

        let additional = map
            .iter()
            .find(|&(key, _value)| key.is_empty())
            .map(|(_key, value)| *value);

        MerkleNode::Branch(nodes, additional)
    }
}
