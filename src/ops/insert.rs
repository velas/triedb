use rlp::{self, Rlp};

use crate::{
    merkle::{empty_nodes, nibble::NibbleVec, MerkleNode, MerkleValue},
    Change, Database,
};

pub struct Pair<'a> {
    key: NibbleVec,
    value: &'a [u8],
}

impl<'a> Pair<'a> {
    pub fn new(key: NibbleVec, value: &'a [u8]) -> Self {
        Self { key, value }
    }
}
pub struct PairExt<'a> {
    key: NibbleVec,
    value: MerkleValue<'a>,
}

impl<'a> PairExt<'a> {
    pub fn new(key: NibbleVec, value: MerkleValue<'a>) -> Self {
        Self { key, value }
    }
}

fn value_and_leaf_branch<'a>(a: PairExt<'a>, b: Pair<'a>) -> (MerkleNode<'a>, Change) {
    debug_assert!(!a.key.is_empty());

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    let ai: usize = a.key[0].into();
    let asub: NibbleVec = a.key[1..].into();

    if !asub.is_empty() {
        let branch = change.add_value(&MerkleNode::Extension(asub, a.value));
        nodes[ai] = branch;
    } else {
        nodes[ai] = a.value;
    }

    if b.key.is_empty() {
        additional = Some(b.value);
    } else {
        let bi: usize = b.key[0].into();
        debug_assert!(ai != bi);

        let bsub = b.key[1..].into();
        let branch = change.add_value(&MerkleNode::Leaf(bsub, b.value));

        nodes[bi] = branch;
    }

    (MerkleNode::Branch(nodes, additional), change)
}

fn two_leaf_branch<'a>(a: Pair<'a>, b: Pair<'a>) -> (MerkleNode<'a>, Change) {
    debug_assert!(b.key.is_empty() || !a.key.starts_with(&b.key));
    debug_assert!(a.key.is_empty() || !b.key.starts_with(&a.key));

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    if a.key.is_empty() {
        additional = Some(a.value);
    } else {
        let ai: usize = a.key[0].into();
        let asub: NibbleVec = a.key[1..].into();
        let branch = change.add_value(&MerkleNode::Leaf(asub, a.value));
        nodes[ai] = branch;
    }

    if b.key.is_empty() {
        additional = Some(b.value);
    } else {
        let bi: usize = b.key[0].into();
        let bsub: NibbleVec = b.key[1..].into();
        let branch = change.add_value(&MerkleNode::Leaf(bsub, b.value));
        nodes[bi] = branch;
    }

    (MerkleNode::Branch(nodes, additional), change)
}

pub fn get_value<'a, D: Database>(
    node: MerkleNode<'a>,
    inserted: Pair<'a>,
    database: &'a D,
    change: &mut Change,
) -> MerkleValue<'a> {
    let (new_node, subchange) = insert_by_node(node, inserted, database);
    change.merge(&subchange);
    change.add_value(&new_node)
}

pub fn insert_by_value<'a, D: Database>(
    merkle: MerkleValue<'a>,
    inserted: Pair<'a>,
    database: &'a D,
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => change.add_value(&MerkleNode::Leaf(inserted.key, inserted.value)),
        MerkleValue::Full(ref sub_node) => {
            let sub_node = sub_node.as_ref().clone();
            get_value(sub_node, inserted, database, &mut change)
        }
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)))
                .expect("Unable to decide Node value");
            change.remove_node(&sub_node);
            get_value(sub_node, inserted, database, &mut change)
        }
    };

    (new, change)
}

mod insert_by_node {
    use crate::merkle::nibble;
    use crate::merkle::MerkleNode;
    use crate::Change;
    use crate::Database;

    use super::insert_by_value;
    use super::two_leaf_branch;
    use super::value_and_leaf_branch;
    use super::{Pair, PairExt};

    pub fn leaf<'a: 'b, 'b>(
        node: &'b MerkleNode<'a>,
        inserted: Pair<'a>,
    ) -> (MerkleNode<'a>, Change) {
        if let MerkleNode::Leaf(key, value) = node {
            let mut change = Change::default();

            let new = if key == &inserted.key {
                MerkleNode::Leaf(inserted.key, inserted.value)
            } else {
                let (common, inserted_key_sub, key_sub) =
                    nibble::common_with_sub(&inserted.key, key);

                let (branch, subchange) = two_leaf_branch(
                    Pair::new(key_sub, value),
                    Pair::new(inserted_key_sub, inserted.value),
                );
                change.merge(&subchange);
                if !common.is_empty() {
                    MerkleNode::Extension(common.into(), change.add_value(&branch))
                } else {
                    branch
                }
            };
            (new, change)
        } else {
            unreachable!();
        }
    }
    pub fn extension<'a: 'b, 'b, D: Database>(
        node: &'b MerkleNode<'a>,
        inserted: Pair<'a>,
        database: &'a D,
    ) -> (MerkleNode<'a>, Change) {
        if let MerkleNode::Extension(key, value) = node {
            let mut change = Change::default();
            let new = if inserted.key.starts_with(key) {
                let (subvalue, subchange) = insert_by_value(
                    value.clone(),
                    Pair::new(inserted.key[key.len()..].into(), inserted.value),
                    database,
                );
                change.merge(&subchange);

                MerkleNode::Extension(key.clone(), subvalue)
            } else {
                let (common, inserted_key_sub, key_sub) =
                    nibble::common_with_sub(&inserted.key, key);

                let (branch, subchange) = value_and_leaf_branch(
                    PairExt::new(key_sub, value.clone()),
                    Pair::new(inserted_key_sub, inserted.value),
                );
                change.merge(&subchange);
                if !common.is_empty() {
                    MerkleNode::Extension(common.into(), change.add_value(&branch))
                } else {
                    branch
                }
            };
            (new, change)
        } else {
            unreachable!();
        }
    }

    pub fn branch<'a: 'b, 'b, D: Database>(
        node: &'b MerkleNode<'a>,
        inserted: Pair<'a>,
        database: &'a D,
    ) -> (MerkleNode<'a>, Change) {
        if let MerkleNode::Branch(nodes, value) = node {
            let mut change = Change::default();
            let mut nodes = nodes.clone();
            let new = if inserted.key.is_empty() {
                MerkleNode::Branch(nodes, Some(inserted.value))
            } else {
                let ni: usize = inserted.key[0].into();
                let prev = nodes[ni].clone();
                let (new, subchange) = insert_by_value(
                    prev,
                    Pair::new(inserted.key[1..].into(), inserted.value),
                    database,
                );
                change.merge(&subchange);

                nodes[ni] = new;
                MerkleNode::Branch(nodes, *value)
            };
            (new, change)
        } else {
            unreachable!();
        }
    }
}

pub fn insert_by_node<'a, D: Database>(
    node: MerkleNode<'a>,
    inserted: Pair<'a>,
    database: &'a D,
) -> (MerkleNode<'a>, Change) {
    let (new, change) = match &node {
        MerkleNode::Leaf(..) => insert_by_node::leaf(&node, inserted),
        MerkleNode::Extension(..) => insert_by_node::extension(&node, inserted, database),
        MerkleNode::Branch(..) => insert_by_node::branch(&node, inserted, database),
    };

    (new, change)
}

pub fn insert_by_empty(nibble: NibbleVec, value: &[u8]) -> (MerkleNode<'_>, Change) {
    let new = MerkleNode::Leaf(nibble, value);
    (new, Change::default())
}
