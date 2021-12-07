use rlp::{self, Rlp};

use crate::{
    database::DatabaseMut,
    merkle::{
        empty_nodes,
        nibble::{self, NibbleVec},
        MerkleNode, MerkleValue,
    },
};

trait GetExt: DatabaseMut + BasicOps {
    fn value_and_leaf_branch<'a>(
        &self,
        anibble: NibbleVec,
        avalue: MerkleValue<'a>,
        bnibble: NibbleVec,
        bvalue: &'a [u8],
    ) -> Result<Hashed<MerkleNode<'a>>> {
        debug_assert!(!anibble.is_empty());

        let mut additional = None;
        let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

        let ai: usize = anibble[0].into();
        let asub: NibbleVec = anibble[1..].into();

        if !asub.is_empty() {
            let ext_value = self.add_value(&MerkleNode::Extension(asub, avalue))?;
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
            let bvalue = self.add_value(&MerkleNode::Leaf(bsub, bvalue))?;

            nodes[bi] = bvalue;
        }

        MerkleNode::Branch(nodes, additional).into()
    }

    fn two_leaf_branch<'a>(
        &self,
        anibble: NibbleVec,
        avalue: &'a [u8],
        bnibble: NibbleVec,
        bvalue: &'a [u8],
    ) -> Result<Hashed<MerkleNode<'a>>> {
        debug_assert!(bnibble.is_empty() || !anibble.starts_with(&bnibble));
        debug_assert!(anibble.is_empty() || !bnibble.starts_with(&anibble));

        let mut additional = None;
        let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

        if anibble.is_empty() {
            additional = Some(avalue);
        } else {
            let ai: usize = anibble[0].into();
            let asub: NibbleVec = anibble[1..].into();
            let avalue = self.add_value(&MerkleNode::Leaf(asub, avalue))?;
            nodes[ai] = avalue;
        }

        if bnibble.is_empty() {
            additional = Some(bvalue);
        } else {
            let bi: usize = bnibble[0].into();
            let bsub: NibbleVec = bnibble[1..].into();
            let bvalue = self.add_value(&MerkleNode::Leaf(bsub, bvalue))?;
            nodes[bi] = bvalue;
        }

        MerkleNode::Branch(nodes, additional).into()
    }

    fn insert_by_value<'a>(
        &self,
        merkle: MerkleValue<'a>,
        nibble: NibbleVec,
        value: &'a [u8],
    ) -> Hashed<MerkleValue<'a>> {
        let new = match merkle {
            MerkleValue::Empty => self.add_value(&MerkleNode::Leaf(nibble, value)),
            MerkleValue::Full(ref mut sub_node) => {
                let mut new_node = self.insert_by_node(sub_node, nibble, value, database)?;
                self.add_value(&mut new_node)
            }
            MerkleValue::Hash(h) => {
                let mut sub_node = database.get_node(h);
                self.remove_node(&mut sub_node)?;
                let (new_node, subchange) =
                    self.insert_by_node(sub_node, nibble, value, database)?;
                self.add_value(&mut new_node)?
            }
        };

        new
    }

    fn insert_by_node<'a>(
        &self,
        node: MerkleNode<'a>,
        nibble: NibbleVec,
        value: &'a [u8],
        database: &'a D,
    ) -> Hashed<MerkleNode<'a>> {
        let mut change = Change::default();

        let new = match node {
            MerkleNode::Leaf(ref node_nibble, ref node_value) => {
                if node_nibble == &nibble {
                    MerkleNode::Leaf(nibble, value)
                } else {
                    let (common, nibble_sub, node_nibble_sub) =
                        nibble::common_with_sub(&nibble, &node_nibble);

                    let branch =
                        self.two_leaf_branch(node_nibble_sub, node_value, nibble_sub, value);
                    if !common.is_empty() {
                        MerkleNode::Extension(common.into(), self.add_value(&branch))
                    } else {
                        branch
                    }
                }
            }
            MerkleNode::Extension(ref node_nibble, ref node_value) => {
                if nibble.starts_with(node_nibble) {
                    let subvalue = self.insert_by_value(
                        node_value.clone(),
                        nibble[node_nibble.len()..].into(),
                        value,
                    );

                    MerkleNode::Extension(node_nibble.clone(), subvalue)
                } else {
                    let (common, nibble_sub, node_nibble_sub) =
                        nibble::common_with_sub(&nibble, &node_nibble);

                    let branch = value_and_leaf_branch(
                        node_nibble_sub,
                        node_value.clone(),
                        nibble_sub,
                        value,
                    );
                    if !common.is_empty() {
                        MerkleNode::Extension(common.into(), self.add_value(&branch))
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
                    let new = self.insert_by_value(prev, nibble[1..].into(), value, database);

                    nodes[ni] = new;
                    MerkleNode::Branch(nodes, *node_additional)
                }
            }
        };

        new
    }

    fn insert_by_empty(&self, nibble: NibbleVec, value: &[u8]) -> Hashed<MerkleNode<'_>> {
        let new = MerkleNode::Leaf(nibble, value);
        new.into()
    }
}
