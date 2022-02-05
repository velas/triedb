use primitive_types::H256;
use rlp::{self, Rlp};

use crate::database::DatabaseMut;
use crate::merkle::{
    empty_nodes,
    nibble::{self, NibbleVec},
    MerkleNode, MerkleValue,
};

fn value_and_leaf_branch<'a, D: DatabaseMut, F: FnMut(&[u8]) -> Vec<H256> + Clone>(
    database: &'a D,
    anibble: NibbleVec,
    avalue: MerkleValue<'a>,
    bnibble: NibbleVec,
    bvalue: &'a [u8],
    child_extractor: F,
) -> MerkleNode<'a> {
    debug_assert!(!anibble.is_empty());

    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    let ai: usize = anibble[0].into();
    let asub: NibbleVec = anibble[1..].into();

    if !asub.is_empty() {
        let ext_value = crate::add_value(
            database,
            &MerkleNode::Extension(asub, avalue),
            child_extractor.clone(),
        );
        nodes[ai] = ext_value;
    } else {
        nodes[ai] = avalue;
    }

    if bnibble.is_empty() {
        additional = Some(bvalue);
    } else {
        let bi: usize = bnibble[0].into();
        debug_assert!(ai != bi);

        let bsub = bnibble[1..].into();
        let bvalue = crate::add_value(database, &MerkleNode::Leaf(bsub, bvalue), child_extractor);

        nodes[bi] = bvalue;
    }

    MerkleNode::Branch(nodes, additional)
}

fn two_leaf_branch<'a, D: DatabaseMut, F: FnMut(&[u8]) -> Vec<H256> + Clone>(
    database: &'a D,
    anibble: NibbleVec,
    avalue: &'a [u8],
    bnibble: NibbleVec,
    bvalue: &'a [u8],
    child_extractor: F,
) -> MerkleNode<'a> {
    debug_assert!(bnibble.is_empty() || !anibble.starts_with(&bnibble));
    debug_assert!(anibble.is_empty() || !bnibble.starts_with(&anibble));

    // let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    if anibble.is_empty() {
        additional = Some(avalue);
    } else {
        let ai: usize = anibble[0].into();
        let asub: NibbleVec = anibble[1..].into();
        let avalue = crate::add_value(
            database,
            &MerkleNode::Leaf(asub, avalue),
            child_extractor.clone(),
        );
        nodes[ai] = avalue;
    }

    if bnibble.is_empty() {
        additional = Some(bvalue);
    } else {
        let bi: usize = bnibble[0].into();
        let bsub: NibbleVec = bnibble[1..].into();
        let bvalue = crate::add_value(database, &MerkleNode::Leaf(bsub, bvalue), child_extractor);
        nodes[bi] = bvalue;
    }

    MerkleNode::Branch(nodes, additional)
}

pub fn insert_by_value<'a, D, F>(
    merkle: MerkleValue<'a>,
    nibble: NibbleVec,
    value: &'a [u8],
    database: &'a D,
    child_extractor: F,
) -> MerkleValue<'a>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    match merkle {
        MerkleValue::Empty => {
            crate::add_value(database, &MerkleNode::Leaf(nibble, value), child_extractor)
        }
        MerkleValue::Full(sub_node) => {
            let new_node =
                insert_by_node(*sub_node, nibble, value, database, child_extractor.clone());
            crate::add_value(database, &new_node, child_extractor)
        }
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)))
                .expect("Unable to decide Node value");
            database.gc_try_cleanup_node(h, child_extractor.clone());
            let new_node =
                insert_by_node(sub_node, nibble, value, database, child_extractor.clone());
            crate::add_value(database, &new_node, child_extractor)
        }
    }
}

pub fn insert_by_node<'a, D, F>(
    node: MerkleNode<'a>,
    nibble: NibbleVec,
    value: &'a [u8],
    database: &'a D,
    child_extractor: F,
) -> MerkleNode<'a>
where
    D: DatabaseMut,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    match node {
        MerkleNode::Leaf(node_nibble, node_value) => {
            if node_nibble == nibble {
                MerkleNode::Leaf(nibble, value)
            } else {
                let (common, nibble_sub, node_nibble_sub) =
                    nibble::common_with_sub(&nibble, &node_nibble);

                let branch = two_leaf_branch(
                    database,
                    node_nibble_sub,
                    node_value,
                    nibble_sub,
                    value,
                    child_extractor.clone(),
                );
                if !common.is_empty() {
                    MerkleNode::Extension(
                        common.into(),
                        crate::add_value(database, &branch, child_extractor),
                    )
                } else {
                    branch
                }
            }
        }
        MerkleNode::Extension(node_nibble, node_value) => {
            if nibble.starts_with(&node_nibble) {
                let subvalue = insert_by_value(
                    node_value,
                    nibble[node_nibble.len()..].into(),
                    value,
                    database,
                    child_extractor,
                );

                MerkleNode::Extension(node_nibble, subvalue)
            } else {
                let (common, nibble_sub, node_nibble_sub) =
                    nibble::common_with_sub(&nibble, &node_nibble);

                let branch = value_and_leaf_branch(
                    database,
                    node_nibble_sub,
                    node_value,
                    nibble_sub,
                    value,
                    child_extractor.clone(),
                );
                if !common.is_empty() {
                    MerkleNode::Extension(
                        common.into(),
                        crate::add_value(database, &branch, child_extractor),
                    )
                } else {
                    branch
                }
            }
        }
        MerkleNode::Branch(node_nodes, node_additional) => {
            let mut nodes = node_nodes;
            if nibble.is_empty() {
                MerkleNode::Branch(nodes, Some(value))
            } else {
                let ni: usize = nibble[0].into();
                let prev = nodes[ni].clone();
                let new =
                    insert_by_value(prev, nibble[1..].into(), value, database, child_extractor);

                nodes[ni] = new;
                MerkleNode::Branch(nodes, node_additional)
            }
        }
    }
}

pub fn insert_by_empty(nibble: NibbleVec, value: &[u8]) -> MerkleNode<'_> {
    MerkleNode::Leaf(nibble, value)
}
