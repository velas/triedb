use primitive_types::H256;
use rlp::{self, Rlp};

use crate::{
    database::DatabaseMut,
    merkle::{
        nibble::{Nibble, NibbleVec},
        MerkleNode, MerkleValue,
    },
    Database,
};

fn find_and_remove_child<'a, D: Database>(
    merkle: MerkleValue<'a>,
    database: &'a D,
) -> MerkleNode<'a> {
    match merkle {
        MerkleValue::Empty => panic!(),
        MerkleValue::Full(sub_node) => *sub_node,
        MerkleValue::Hash(h) => {
            let sub_node =
                MerkleNode::decode(&Rlp::new(database.get(h))).expect("Unable to decode value");
            // change.remove_node(&sub_node); FIXME: remove_node and remove_raw
            sub_node
        }
    }
}

fn collapse_extension<'a, D, F>(
    database: &'a D,
    mut node_nibble: NibbleVec,
    subnode: MerkleNode<'a>,
    child_extractor: F,
) -> MerkleNode<'a>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256>,
{
    match subnode {
        MerkleNode::Leaf(mut sub_nibble, sub_value) => {
            node_nibble.append(&mut sub_nibble);
            MerkleNode::Leaf(node_nibble, sub_value)
        }
        MerkleNode::Extension(mut sub_nibble, sub_value) => {
            debug_assert!(sub_value != MerkleValue::Empty);

            node_nibble.append(&mut sub_nibble);
            MerkleNode::Extension(node_nibble, sub_value)
        }
        branch => {
            let subvalue = crate::add_value(database, &branch, child_extractor);
            MerkleNode::Extension(node_nibble, subvalue)
        }
    }
}

fn nonempty_node_count<'a, 'b>(
    nodes: &'b [MerkleValue<'a>; 16],
    additional: &'b Option<&'a [u8]>,
) -> usize {
    additional.iter().count() + nodes.iter().filter(|v| v != &&MerkleValue::Empty).count()
}

fn collapse_branch<'a, D, F>(
    node_nodes: [MerkleValue<'a>; 16],
    node_additional: Option<&'a [u8]>,
    database: &'a D,
    child_extractor: F,
) -> MerkleNode<'a>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    let value_count = nonempty_node_count(&node_nodes, &node_additional);

    match value_count {
        0 => panic!(),
        1 if node_additional.is_some() =>
            MerkleNode::Leaf(NibbleVec::new(), node_additional.unwrap()),
        1 /* value in node_nodes */ => {
            let (subindex, subvalue) = node_nodes.iter().enumerate()
                .find(|&(_, v)| v != &MerkleValue::Empty)
                .map(|(i, v)| (i, v.clone())).unwrap();
            let subnibble =  Nibble::from(subindex);

            let subnode = find_and_remove_child(subvalue, database);

            match subnode {
                MerkleNode::Leaf(mut leaf_nibble, leaf_value) => {
                    leaf_nibble.insert(0, subnibble);
                    MerkleNode::Leaf(leaf_nibble, leaf_value)
                },
                MerkleNode::Extension(mut ext_nibble, ext_value) => {
                    debug_assert!(ext_value != MerkleValue::Empty);

                    ext_nibble.insert(0, subnibble);
                    MerkleNode::Extension(ext_nibble, ext_value)
                },
                branch => {
                    let subvalue = crate::add_value(database, &branch, child_extractor);
                    MerkleNode::Extension(vec![subnibble], subvalue)
                },
            }
        },
        _ /* value_count > 1 */ =>
            MerkleNode::Branch(node_nodes, node_additional),
    }
}

pub fn delete_by_child<'a, D, F>(
    merkle: MerkleValue<'a>,
    nibble: NibbleVec,
    database: &'a D,
    child_extractor: F,
) -> Option<MerkleNode<'a>>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    match merkle {
        MerkleValue::Empty => None,
        MerkleValue::Full(sub_node) => delete_by_node(*sub_node, nibble, database, child_extractor),
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)))
                .expect("Unable to decode Node value");
            // crate::remove_node(&sub_node, ); // FIXME: implement
            delete_by_node(sub_node, nibble, database, child_extractor)
        }
    }
}

pub fn delete_by_node<'a, D, F>(
    node: MerkleNode<'a>,
    nibble: NibbleVec,
    database: &'a D,
    child_extractor: F,
) -> Option<MerkleNode<'a>>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    match node {
        MerkleNode::Leaf(node_nibble, node_value) => {
            if node_nibble == nibble {
                None
            } else {
                Some(MerkleNode::Leaf(node_nibble, node_value))
            }
        }
        MerkleNode::Extension(node_nibble, node_value) => {
            if nibble.starts_with(&node_nibble) {
                let subnode = delete_by_child(
                    node_value,
                    nibble[node_nibble.len()..].into(),
                    database,
                    child_extractor.clone(),
                );
                subnode.map(|subnode| {
                    collapse_extension(database, node_nibble, subnode, child_extractor)
                })
            } else {
                Some(MerkleNode::Extension(node_nibble, node_value))
            }
        }
        MerkleNode::Branch(mut node_nodes, mut node_additional) => {
            let needs_collapse;

            if nibble.is_empty() {
                node_additional = None;
                needs_collapse = true;
            } else {
                let ni: usize = nibble[0].into();
                let new_subnode = delete_by_child(
                    node_nodes[ni].clone(),
                    nibble[1..].into(),
                    database,
                    child_extractor.clone(),
                );

                match new_subnode {
                    Some(new_subnode) => {
                        node_nodes[ni] =
                            crate::add_value(database, &new_subnode, child_extractor.clone());
                        needs_collapse = false;
                    }
                    None => {
                        node_nodes[ni] = MerkleValue::Empty;
                        needs_collapse = true;
                    }
                }
            }

            if needs_collapse {
                let value_count = nonempty_node_count(&node_nodes, &node_additional);
                if value_count > 0 {
                    Some(collapse_branch(
                        node_nodes,
                        node_additional,
                        database,
                        child_extractor,
                    ))
                } else {
                    None
                }
            } else {
                Some(MerkleNode::Branch(node_nodes, node_additional))
            }
        }
    }
}
