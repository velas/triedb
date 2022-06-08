use std::borrow::Borrow;
use std::sync::RwLock;

use crate::merkle::nibble::{self, Nibble, NibbleSlice, NibbleVec};
use crate::merkle::{MerkleNode, MerkleValue};
use primitive_types::H256;
use rlp::Rlp;

// use crate::rocksdb::OptimisticTransactionDB;
use rocksdb_lib::{ColumnFamily, MergeOperands, OptimisticTransactionDB};

#[derive(Debug)]
pub struct StateTraversal<DB> {
    pub db: DB,
    pub start_state_root: H256,
    pub end_state_root: H256,
    changeset: RwLock<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Cursor {
    nibble: NibbleVec,
    current_hash: H256,
}

#[derive(Debug, Clone)]
enum Change {
    Insert(H256, Vec<u8>),
    Removal(H256, Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ComparePathResult {
    // Left NibbleVec contain additional nibbles
    // Example:
    // key1: bb33
    // key2: bb3
    LeftDeeper,
    // Right NibbleVec contain additional nibbles
    // Example:
    // key1: aabb
    // key2: aabb1e
    RightDeeper,
    // Right and Left NibbleVec are the same
    // Example:
    // key1: aabb1e
    // key2: aabb1e
    SamePath,
    // Left and Right paths contain different postfixes, and cannot be compared
    // Example:
    // key1: aabBcc
    // key2: aabEcc
    Uncomparable,
}

impl<DB: Borrow<OptimisticTransactionDB> + Sync + Send> StateTraversal<DB> {
    pub fn new(db: DB, start_state_root: H256, end_state_root: H256) -> Self {
        StateTraversal {
            db,
            start_state_root,
            end_state_root,
            changeset: RwLock::new(Vec::new()),
        }
    }

    pub fn get_changeset(&self) -> Result<Vec<u8>, ()> {
        self.traverse_inner(
            Default::default(),
            Default::default(),
            self.start_state_root,
            self.end_state_root,
        );
        let reader = self
            .changeset
            .read()
            .expect("Should receive a reader to changeset");
        Ok(reader.clone())
    }

    fn traverse_inner(
        &self,
        left_nibble: NibbleVec,
        right_nibble: NibbleVec,
        left_tree_cursor: H256,
        right_tree_cursor: H256,
    ) -> Result<Vec<u8>, ()> {
        eprintln!("traversing left tree{:?} ...", left_tree_cursor);
        eprintln!("traversing rigth tree{:?} ...", right_tree_cursor);

        let right_node;
        let left_node;

        // Left tree value
        if left_tree_cursor != crate::empty_trie_hash() {
            let db = self.db.borrow();
            let bytes = db
                .get(left_tree_cursor)
                .map_err(|_| ())?
                .ok_or_else(|| panic!("paniking in left tree byte parsing"))?;
            eprintln!("left raw bytes: {:?}", bytes);

            let rlp = Rlp::new(bytes.as_slice());
            eprintln!("left rlp: {:?}", rlp);

            let node = MerkleNode::decode(&rlp).map_err(|e| panic!("left merkle rlp decode"))?;
            eprintln!("left node: {:?}", node);

            left_node = node;

            // Right tree value
            if right_tree_cursor != crate::empty_trie_hash() {
                let db = self.db.borrow();
                let bytes = db
                    .get(right_tree_cursor)
                    .map_err(|_| ())?
                    .ok_or_else(|| panic!("paniking in rigth tree byte parsing"))?;
                eprintln!("right raw bytes: {:?}", bytes);

                let rlp = Rlp::new(bytes.as_slice());
                eprintln!("right rlp: {:?}", rlp);

                let node =
                    MerkleNode::decode(&rlp).map_err(|e| panic!("left merkle rlp decode"))?;
                eprintln!("right node: {:?}", node);

                right_node = node;

                self.compare_nodes(left_nibble, &left_node, right_nibble, &right_node);
            } else {
                eprintln!("skip empty right trie");
                // Guard to remove
                return Ok(Vec::new());
            }
        } else {
            eprintln!("skip empty left trie");
            // Guard to remove
            return Ok(Vec::new());
        }

        // if left_node != right_node {
        //   self.process_node(right_nibble, &right_node)?;
        // }

        Ok(vec![])
    }

    fn compare_nodes(
        &self,
        left_nibble: NibbleVec,
        left_node: &MerkleNode,
        right_nibble: NibbleVec,
        right_node: &MerkleNode,
    ) -> Vec<Change> {
        let mut changes = vec![];
        // TODO: check hash is enough there
        if left_node == right_node {
            // if nodes are same - then left tree already contain this node - no reason to traverse it
            // return empty list
            return changes;
        }

        let branch_level = Self::check_branch_level(&left_nibble, &right_nibble);
        match branch_level {
            // We found two completely different paths
            ComparePathResult::Uncomparable => {
                changes.extend_from_slice(&self.remowe_swallow(left_nibble, left_node));
                changes.extend_from_slice(&self.insert_swallow(right_nibble, right_node));
                return changes;
            }
            // We always trying to keep this function on same level, or when right nodes are deeper.
            // Traverse right side.
            ComparePathResult::LeftDeeper => {
                changes.extend_from_slice(&Self::reverse_changes(self.compare_nodes(
                    right_nibble,
                    right_node,
                    left_nibble,
                    left_node,
                )));
                return changes;
            }
            ComparePathResult::RightDeeper | ComparePathResult::SamePath => {}
        };

        match (left_node, right_node) {
            // One leaf was replaced by other. (data changed)
            (MerkleNode::Leaf(_lnibbles, ldata), MerkleNode::Leaf(rnibbles, rdata)) => {
                assert!(
                    left_nibble != right_nibble || ldata != rdata,
                    "Found different nodes, with same prefix and data"
                );
                assert_eq!(
                    left_nibble.len(),
                    right_nibble.len(),
                    "Diff work only with fixed sized key"
                );
                // if node is not same then it replace of new node
                changes.push(Change::remove(left_node));
                changes.push(Change::insert(right_node))
            }
            // Leaf was replaced by subtree.
            (MerkleNode::Leaf(_lnibbles, ldata), rnode) => {
                changes.push(Change::remove(left_node));
                changes.extend_from_slice(&self.insert_swallow(right_nibble, rnode));
            }
            // We found extension at left part that differ from node from right.
            // Go deeper to find any branch or leaf.
            (MerkleNode::Extension(lnibbles, ldata), rnode) => {
                changes.push(Change::remove(left_node));
                let e_nibbles = {
                    let mut ln = left_nibble.clone();
                    ln.extend_from_slice(&lnibbles);
                    ln
                };
                changes.extend_from_slice(&self.walk_extension(
                    e_nibbles,
                    ldata,
                    right_nibble,
                    right_node,
                ));
            }
            // Branches on same level, but values were changed.
            (MerkleNode::Branch(lvalues, left_data), MerkleNode::Branch(rvalues, right_data))
                if branch_level == ComparePathResult::SamePath =>
            {
                assert!(
                    left_data.is_none(),
                    "We support only fixed sized keys in diff"
                );
                assert!(
                    right_data.is_none(),
                    "We support only fixed sized keys in diff"
                );
                for (left_value, right_value) in lvalues.zip(rvalues) {
                    let b_nibble = {
                        let mut rn = right_nibble.clone();
                        rn.push(Nibble::from(index));
                        rn
                    };
                    match (right_value.node(db), left_value.node(db)) {
                        (Some(lnode), Some(rnode)) => changes.extend_from_slice(
                            &self.compare_nodes(b_nibble, left_node, b_nibble, right_node),
                        ),
                        (Some(lnode), None) => changes.push(Change::remove(lnode)),
                        (None, Some(rnode)) => changes.push(Change::insert(lnode)),
                        (None, None) => {}
                    }
                }
            }
            (MerkleNode::Branch(values, mb_data), rnode) => {
                changes.extend_from_slice(&self.walk_branch(
                    left_nibble,
                    values,
                    mb_data,
                    right_nibble,
                    right_node,
                ));
            } // We can make shortcut for leaf.
              // (lnode, MerkleNode::Leaf(_lnibbles, rdata)) => {
              //     changes.push(Change::insert(right_node));
              //     changes.extend_from_slice(self.remove_swallow(left_nibble, lnode));
              // }

              // But all this cases:
              // (lnode, MerkleNode::Extension(..)) |
              // (lnode, MerkleNode::Leaf(..)) |
              // (lnode, MerkleNode::Branch(..))
              // were already covered by above match branches.
        }
        return changes;
    }

    fn check_branch_level(left_slice: NibbleSlice, right_slice: NibbleSlice) -> ComparePathResult {
        let common = nibble::common(&left_slice, &right_slice);
        match (
            common.len() != left_slice.len(),
            common.len() != right_slice.len(),
        ) {
            (true, false) => ComparePathResult::LeftDeeper,
            (false, true) => ComparePathResult::RightDeeper,
            (true, true) => ComparePathResult::Uncomparable,
            (false, false) => ComparePathResult::SamePath,
        }
    }

    // Find branch for right_ndoe and walk deeper into one of branch
    fn walk_branch(
        &self,
        left_nibble_prefix: NibbleVec,
        left_values: &[MerkleValue; 16],
        mb_data: &Option<&[u8]>,
        right_nibble: NibbleVec,
        right_node: &MerkleNode,
    ) -> Vec<Change> {
        // Found a data in branch - it's a marker that key is not fixed sized.
        assert!(
            mb_data.is_none(),
            "We support only fixed sized keys in diff"
        );

        let mut changes = vec![Change::insert(right_node)];

        let mut right_nibble_with_postfix = right_nibble.clone();
        if let Some(rnibble_postfix) = right_node.nibble() {
            right_nibble_with_postfix.extend_from_slice(&rnibble_postfix)
        }

        let (common, left_postfix, right_postfix) =
            nibble::common_with_sub(&left_nibble_prefix, &right_nibble_with_postfix);
        assert!(
            left_postfix.is_empty(),
            "left tree should have smaller path in order to find changed node in branch."
        );
        let r_index = right_postfix[0]; // find first different nibble

        for (index, value) in left_values.into_iter().enumerate() {
            let b_nibble = {
                let mut rn = right_nibble.clone();
                rn.push(Nibble::from(index));
                rn
            };
            if let Some(b_node) = value.node(db) {
                // Compare changed nodes
                if r_index == index {
                    changes.extend_from_slice(&self.compare_nodes(
                        b_nibble,
                        b_node,
                        right_nibble,
                        right_node,
                    ));
                } else {
                    changes.extend_from_slice(self.insert_swallow(b_nibble, b_node))
                }
            } else {
                log::trace!("Node {} was not found in branch", b_nibble);
            }
        }
        changes
    }

    // Walk deeper into extension
    fn walk_extension(
        &self,
        left_nibble: NibbleVec,
        left_value: &MerkleValue,
        right_nibble: NibbleVec,
        right_node: &MerkleNode,
    ) -> Vec<Change> {
        let left_node = left_value
            .node(self.db.borrow())
            .expect("Extension should never link to empty value");
        self.compare_nodes(left_nibble, left_node, right_nibble, right_node)
    }

    // We should compare the tags of MerkleNode and understarand if two
    // tags are different. In this case we might traverse the fresh tree and
    // and collect all inserts into the changeset.
    // 32 байта
    // fn process_node(&self, mut nibble: NibbleVec, node: &MerkleNode) -> Result<Vec<u8>, ()> {
    //     // Leaf Extension =>
    //     // Extension Branch
    //     // Branch Leaf
    //     // Leaf Branch =>
    //     //     Branch Branch

    //     match node {
    //         MerkleNode::Leaf(nibbles, data) => {
    //             nibble.extend_from_slice(&*nibbles);
    //             let key = triedb::merkle::nibble::into_key(&nibble);
    //             // self.changeset.push(key, data); optional
    //             Ok(vec![])
    //         }
    //         MerkleNode::Extension(nibbles, value) => {
    //             nibble.extend_from_slice(&*nibbles);
    //             self.process_value(nibble, value);
    //             Ok(vec![])
    //         }
    //         MerkleNode::Branch(values, mb_data) => {
    //             // lack of copy on result, forces setting array manually
    //             let mut values_result = [
    //                 None, None, None, None, None, None, None, None, None, None, None, None, None,
    //                 None, None, None,
    //             ];
    //             let result : Result<Vec<u8>, ()> = rayon::scope(|s| {
    //                 for (nibbl, (value, result)) in
    //                     values.iter().zip(&mut values_result).enumerate()
    //                 {
    //                     let mut cloned_nibble = nibble.clone();
    //                     s.spawn(move |_| {
    //                         cloned_nibble.push(nibbl.into());
    //                         *result = Some(self.process_value(cloned_nibble, value))
    //                     });
    //                 }
    //                 if let Some(data) = mb_data {
    //                     let key = triedb::merkle::nibble::into_key(&nibble);
    //                     // self.changeset.push(key, data); optional
    //                     Ok(vec![])
    //                 } else {
    //                     Ok(vec![])
    //                 }
    //             });
    //             for result in values_result {
    //                 result.unwrap()?;
    //             }
    //             Ok(vec![])
    //         }
    //     }
    // }

    // fn process_value(&self, nibble: NibbleVec, value: &MerkleValue) -> Result<Vec<u8>, ()> {
    //     match value {
    //         MerkleValue::Empty => Ok(vec![]),
    //         MerkleValue::Full(node) => self.process_node(nibble, node),
    //         MerkleValue::Hash(hash) => self.traverse_inner(nibble, *hash, *hash),
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::gc::MapWithCounterCached;
    use crate::gc::TrieCollection;
    use crate::mutable::TrieMut;

    use super::*;

    // Possible inmemory test
    // #[test]
    // fn test_two_leaves() {
    //     let mut mtrie = MemoryTrieMut::default();
    //     mtrie.insert("key1".as_bytes(), "aval1".as_bytes());
    //     first_root = mtrie.root();

    //     mtrie.insert("key2bb".as_bytes(), "aval3".as_bytes());
    //     second_root = mtrie.root();

    //     // let differ = StateTraversal::new(mtrie, first_root, second_root);
    //     // let changeset = differ.get_changeset();

    //     // assert_eq!(chageset, vec![])
    // }

    #[test]
    fn test_two_same_leaves() {
        let key1 = &hex!("bbaa");
        let key2 = &hex!("ffaa");
        let key3 = &hex!("bbcc");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";
        let value3 = b"other data_______________________";
        let value3_1 = b"changed data_____________________";
        let value2_1 = b"changed data_____________________";

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        trie.insert(key3, value3);

        let patch = trie.into_patch();

        let st = StateTraversal::new(std::sync::Arc::new(trie), patch.root, patch.root);

        assert!(true)
    }
}
