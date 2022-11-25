use rlp::{self, Rlp};

use crate::{
    merkle::{
        empty_nodes,
        nibble::{self, NibbleVec},
        MerkleNode, MerkleValue,
    },
    Change, Database,
};

fn value_and_leaf_branch<'a>(
    anibble: NibbleVec,
    avalue: MerkleValue<'a>,
    bnibble: NibbleVec,
    bvalue: &'a [u8],
) -> (MerkleNode<'a>, Change) {
    debug_assert!(!anibble.is_empty());

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    let ai: usize = anibble[0].into();
    let asub: NibbleVec = anibble[1..].into();

    if !asub.is_empty() {
        let ext_value = change.add_value(&MerkleNode::Extension(asub, avalue));
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
        let bvalue = change.add_value(&MerkleNode::Leaf(bsub, bvalue));

        nodes[bi] = bvalue;
    }

    (MerkleNode::Branch(nodes, additional), change)
}

fn two_leaf_branch<'a>(
    anibble: NibbleVec,
    avalue: &'a [u8],
    bnibble: NibbleVec,
    bvalue: &'a [u8],
) -> (MerkleNode<'a>, Change) {
    debug_assert!(bnibble.is_empty() || !anibble.starts_with(&bnibble));
    debug_assert!(anibble.is_empty() || !bnibble.starts_with(&anibble));

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    if anibble.is_empty() {
        additional = Some(avalue);
    } else {
        let ai: usize = anibble[0].into();
        let asub: NibbleVec = anibble[1..].into();
        let avalue = change.add_value(&MerkleNode::Leaf(asub, avalue));
        nodes[ai] = avalue;
    }

    if bnibble.is_empty() {
        additional = Some(bvalue);
    } else {
        let bi: usize = bnibble[0].into();
        let bsub: NibbleVec = bnibble[1..].into();
        let bvalue = change.add_value(&MerkleNode::Leaf(bsub, bvalue));
        nodes[bi] = bvalue;
    }

    (MerkleNode::Branch(nodes, additional), change)
}

pub fn insert_by_value<'a, D: Database>(
    merkle: MerkleValue<'a>,
    nibble: NibbleVec,
    value: &'a [u8],
    database: &'a D,
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => change.add_value(&MerkleNode::Leaf(nibble, value)),
        MerkleValue::Full(ref sub_node) => {
            let (new_node, subchange) =
                insert_by_node(sub_node.as_ref().clone(), nibble, value, database);
            change.merge(&subchange);
            change.add_value(&new_node)
        }
        MerkleValue::Hash(h) => {
            let mut data = database.get(h);
            let sub_node = <MerkleNode as fastrlp::Decodable>::decode(&mut data)
                .expect("Unable to decide Node value");
            change.remove_node(&sub_node);
            let (new_node, subchange) = insert_by_node(sub_node, nibble, value, database);
            change.merge(&subchange);
            change.add_value(&new_node)
        }
    };

    (new, change)
}

pub fn insert_by_node<'a, D: Database>(
    node: MerkleNode<'a>,
    nibble: NibbleVec,
    value: &'a [u8],
    database: &'a D,
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let new = match node {
        MerkleNode::Leaf(ref node_nibble, node_value) => {
            if node_nibble == &nibble {
                MerkleNode::Leaf(nibble, value)
            } else {
                let (common, nibble_sub, node_nibble_sub) =
                    nibble::common_with_sub(&nibble, node_nibble);

                let (branch, subchange) =
                    two_leaf_branch(node_nibble_sub, node_value, nibble_sub, value);
                change.merge(&subchange);
                if !common.is_empty() {
                    MerkleNode::Extension(common.into(), change.add_value(&branch))
                } else {
                    branch
                }
            }
        }
        MerkleNode::Extension(ref node_nibble, ref node_value) => {
            if nibble.starts_with(node_nibble) {
                let (subvalue, subchange) = insert_by_value(
                    node_value.clone(),
                    nibble[node_nibble.len()..].into(),
                    value,
                    database,
                );
                change.merge(&subchange);

                MerkleNode::Extension(node_nibble.clone(), subvalue)
            } else {
                let (common, nibble_sub, node_nibble_sub) =
                    nibble::common_with_sub(&nibble, node_nibble);

                let (branch, subchange) =
                    value_and_leaf_branch(node_nibble_sub, node_value.clone(), nibble_sub, value);
                change.merge(&subchange);
                if !common.is_empty() {
                    MerkleNode::Extension(common.into(), change.add_value(&branch))
                } else {
                    branch
                }
            }
        }
        MerkleNode::Branch(ref node_nodes, ref node_additional) => {
            let mut nodes = node_nodes.clone();
            if nibble.is_empty() {
                MerkleNode::Branch(nodes, Some(value))
            } else {
                let ni: usize = nibble[0].into();
                let prev = nodes[ni].clone();
                let (new, subchange) = insert_by_value(prev, nibble[1..].into(), value, database);
                change.merge(&subchange);

                nodes[ni] = new;
                MerkleNode::Branch(nodes, *node_additional)
            }
        }
    };

    (new, change)
}

pub fn insert_by_empty(nibble: NibbleVec, value: &[u8]) -> (MerkleNode<'_>, Change) {
    let new = MerkleNode::Leaf(nibble, value);
    (new, Change::default())
}
