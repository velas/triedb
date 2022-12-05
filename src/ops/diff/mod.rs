use std::borrow::Borrow;
use std::ops::{Deref, DerefMut};
use std::sync::RwLock;

use crate::gc::ReachableHashes;
use crate::merkle::nibble::{self, Entry, Nibble, NibbleSlice, NibbleVec};
use crate::merkle::{Branch, Extension, Leaf, MerkleNode, MerkleValue};
use crate::walker::inspector::TrieInspector;
use crate::Database;
use primitive_types::H256;
use rlp::Rlp;

pub mod verify;

#[cfg(test)]
mod tests;

#[cfg(feature = "tracing-enable")]
use tracing::instrument;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Insert(H256, Vec<u8>),
    Removal(H256, Vec<u8>),
}

///
/// Representation of node with data field (Leaf, or Branch when value.is_some())
///
#[derive(Debug, Clone, PartialEq, Eq)]
struct DataNode {
    hash: H256,
    data: Vec<u8>,
}

///
/// Represent data diff between data node.
/// Need for child tries processing.
///
#[derive(Debug, Clone, PartialEq, Eq)]
struct DataNodeChange {
    left: Option<DataNode>,
    right: Option<DataNode>,
}

#[derive(Debug, Default)]
pub struct Changes {
    changes: Vec<Change>,
    // inserts: Vec<(H256, Vec<u8>)>,
    // removes: Vec<(H256, Vec<u8>)>,
    data_diff: Vec<DataNodeChange>,
}
impl Changes {
    #[cfg_attr(feature = "tracing-enable", instrument)]
    fn reverse_changes(self) -> Self {
        let changes = self
            .changes
            .into_iter()
            .map(|i| match i {
                Change::Insert(h, d) => Change::Removal(h, d),
                Change::Removal(h, d) => Change::Insert(h, d),
            })
            .collect();

        let data_diff = self
            .data_diff
            .into_iter()
            .map(|changed|
            // Replace left and right
            DataNodeChange {
                left: changed.right,
                right: changed.left,
            })
            .collect();
        Self { changes, data_diff }
    }

    fn extend(&mut self, other: &Changes) {
        self.changes.extend_from_slice(&other.changes);
        self.data_diff.extend_from_slice(&other.data_diff);
    }

    fn remove_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a>>) {
        if let KeyedMerkleNode::FullEncoded(hash, data) = node.borrow() {
            self.changes.push(Change::Removal(*hash, data.to_vec()))
        } else {
            log::trace!("Skipping to remove inline node")
        }
    }

    fn insert_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a>>) {
        if let KeyedMerkleNode::FullEncoded(hash, data) = node.borrow() {
            self.changes.push(Change::Insert(*hash, data.to_vec()))
        } else {
            log::trace!("Skipping to insert inline node")
        }
    }
}

#[derive(Debug)]
pub(crate) struct DiffFinder<DB, F> {
    pub db: DB,
    child_extractor: F,
}

struct OpCollector<F> {
    changes: RwLock<Changes>,
    func: F,
}
impl<F: Fn(H256, Vec<u8>) -> Change> OpCollector<F> {
    pub fn new(func: F) -> Self {
        Self {
            changes: Default::default(),
            func,
        }
    }
}

impl<F> crate::walker::inspector::TrieInspector for OpCollector<F>
where
    F: Fn(H256, Vec<u8>) -> Change,
{
    fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> anyhow::Result<bool> {
        self.changes
            .write()
            .unwrap()
            .changes
            .push((self.func)(trie_key, node.as_ref().to_vec()));
        Ok(true)
    }
}

struct ChildCollector<F> {
    child_hashes: RwLock<Vec<H256>>,
    child_extractor: F,
}

impl<F: FnMut(&[u8]) -> Vec<H256> + Clone> crate::walker::inspector::TrieDataInsectorRaw
    for ChildCollector<F>
{
    fn inspect_data_raw<Data: AsRef<[u8]>>(
        &self,
        _key: Vec<u8>,
        value: Data,
    ) -> anyhow::Result<()> {
        let childs = (self.child_extractor.clone())(value.as_ref());
        self.child_hashes
            .write()
            .unwrap()
            .extend_from_slice(&childs);
        Ok(())
    }
}

trait MerkleValueExt<'a> {
    fn node(&self, database: &'a impl Database) -> Option<KeyedMerkleNode<'a>>;
}
impl<'a> MerkleValueExt<'a> for MerkleValue<'a> {
    fn node(&self, database: &'a impl Database) -> Option<KeyedMerkleNode<'a>> {
        Some(match self {
            Self::Empty => return None,
            Self::Full(n) => KeyedMerkleNode::Partial(n.deref().clone()),
            Self::Hash(h) => {
                let bytes = database.get(*h);
                KeyedMerkleNode::FullEncoded(*h, bytes)
            }
        })
    }
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

#[derive(Debug, Clone)]
enum KeyedMerkleNode<'a> {
    // Merkle node is only exist as inlined node
    Partial(MerkleNode<'a>),
    FullEncoded(H256, &'a [u8]),
}

impl<'a> KeyedMerkleNode<'a> {
    fn same_hash(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::FullEncoded(h, _), Self::FullEncoded(h2, _)) => h == h2,
            _ => false,
        }
    }
    fn merkle_node(&self) -> MerkleNode {
        match self {
            Self::Partial(n) => n.clone(),
            Self::FullEncoded(_, n) => {
                let rlp = Rlp::new(n);
                MerkleNode::decode(&rlp).expect("Cannot deserialize value")
            }
        }
    }
}

impl<DB: Database + Send + Sync, F: FnMut(&[u8]) -> Vec<H256> + Clone + Send + Sync>
    DiffFinder<DB, F>
{
    pub fn new(db: DB, child_extractor: F) -> Self {
        DiffFinder {
            db,
            child_extractor,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn get_changeset(
        &self,
        start_state_root: H256,
        end_state_root: H256,
    ) -> Result<Vec<Change>, ()> {
        self.compare_roots(
            Default::default(),
            Default::default(),
            start_state_root,
            end_state_root,
        )
        .map(|c| c.changes)
    }

    fn fetch_node(&self, hash: H256) -> KeyedMerkleNode<'_> {
        let bytes = self.db.get(hash);

        KeyedMerkleNode::FullEncoded(hash, bytes)
    }
    fn compare_roots(
        &self,
        left_key: NibbleVec,
        right_key: NibbleVec,
        left_root: H256,
        righ_root: H256,
    ) -> Result<Changes, ()> {
        Ok(
            match (
                left_root == crate::empty_trie_hash(),
                righ_root == crate::empty_trie_hash(),
            ) {
                (true, true) => Changes::default(),
                (true, false) => self.deep_insert(self.fetch_node(righ_root)),
                (false, true) => self.deep_remove(self.fetch_node(left_root)),
                (false, false) => {
                    let left_node = self.fetch_node(left_root);
                    let right_node = self.fetch_node(righ_root);

                    self.compare_nodes(
                        Entry::new(left_key, left_node),
                        Entry::new(right_key, right_node),
                    )
                }
            },
        )
    }

    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn compare_nodes(
        &self,
        left_entry: Entry<KeyedMerkleNode>,
        right_entry: Entry<KeyedMerkleNode>,
    ) -> Changes {
        let mut changes = Changes::default();
        // TODO: check hash is enough there
        if left_entry.value.same_hash(&right_entry.value) {
            // if nodes are same - then left tree already contain this node - no reason to traverse it
            // return empty list
            return changes;
        }

        let branch_level = Self::check_branch_level(&left_entry.nibble, &right_entry.nibble);
        match branch_level {
            // We found two completely different paths
            ComparePathResult::Uncomparable => {
                changes.extend(&self.deep_remove(left_entry.value));
                changes.extend(&self.deep_insert(right_entry.value));
                return changes;
            }
            // We always trying to keep this function on same level, or when right node is deeper.
            // Traverse right side.
            ComparePathResult::LeftDeeper => {
                changes.extend(
                    &self
                        .compare_nodes(right_entry, left_entry)
                        .reverse_changes(),
                );
                return changes;
            }
            ComparePathResult::RightDeeper | ComparePathResult::SamePath => {}
        };
        self.compare_body(branch_level, left_entry, right_entry, changes)
    }
    fn compare_body(
        &self,
        branch_level: ComparePathResult,
        left_entry: Entry<KeyedMerkleNode>,
        right_entry: Entry<KeyedMerkleNode>,
        mut changes: Changes,
    ) -> Changes {
        match (
            left_entry.value.merkle_node(),
            right_entry.value.merkle_node(),
        ) {
            // One leaf was replaced by other. (data changed)
            (
                MerkleNode::Leaf(Leaf {
                    nibbles: lkey,
                    data: ldata,
                }),
                MerkleNode::Leaf(Leaf {
                    nibbles: rkey,
                    data: rdata,
                }),
            ) => {
                if lkey != rkey || ldata != rdata {
                    assert_eq!(
                        left_entry.nibble.len() + lkey.len(),
                        right_entry.nibble.len() + rkey.len(),
                        "Diff work only with fixed sized key"
                    );
                    // if node is not same then it replace of new node
                    changes.extend(&self.deep_remove(left_entry.value));
                    changes.extend(&self.deep_insert(right_entry.value))
                }
            }
            // Leaf was replaced by subtree.
            (
                MerkleNode::Leaf(Leaf {
                    nibbles: _lkey,
                    data: _ldata,
                }),
                _rnode,
            ) => {
                changes.extend(&self.deep_remove(left_entry.value));
                changes.extend(&self.deep_insert(right_entry.value));
            }
            // We found extension at left part that differ from node from right.
            // Go deeper to find any branch or leaf.
            (
                MerkleNode::Extension(Extension {
                    nibbles: ext_key,
                    value: mkl_value,
                }),
                _rnode,
            ) => {
                changes.remove_node(&left_entry.value);
                let full_key = {
                    let mut lk = left_entry.nibble;
                    lk.extend_from_slice(&ext_key);
                    lk
                };
                changes.extend(
                    &self.compare_nodes(
                        Entry::new(full_key, mkl_value)
                            .try_map(|mkl_value| mkl_value.node(self.db.borrow()))
                            .expect(MERKLE_VALUE_EMPTY_EXT_ERR),
                        right_entry,
                    ),
                );
            }
            // Branches on same level, but values were changed.
            (
                MerkleNode::Branch(Branch {
                    childs: left_values,
                    data: left_data,
                }),
                MerkleNode::Branch(Branch {
                    childs: right_values,
                    data: right_data,
                }),
            ) if branch_level == ComparePathResult::SamePath => {
                assert!(
                    left_data.is_none(),
                    "We support only fixed sized keys in diff"
                );
                assert!(
                    right_data.is_none(),
                    "We support only fixed sized keys in diff"
                );
                changes.remove_node(&left_entry.value);
                changes.insert_node(&right_entry.value);
                for (idx, (left_value, right_value)) in
                    left_values.iter().zip(right_values).enumerate()
                {
                    let branch_key = {
                        let mut key = right_entry.nibble.clone(); // || left.key is equal to right.key
                        key.push(Nibble::from(idx));
                        key
                    };
                    match (
                        left_value.node(self.db.borrow()),
                        right_value.node(self.db.borrow()),
                    ) {
                        (Some(lnode), Some(rnode)) => changes.extend(&self.compare_nodes(
                            Entry::new(branch_key.clone(), lnode),
                            Entry::new(branch_key.clone(), rnode),
                        )),
                        (Some(lnode), None) => changes.extend(&self.deep_remove(lnode)),
                        (None, Some(rnode)) => changes.extend(&self.deep_insert(rnode)),
                        (None, None) => {}
                    }
                }
            }
            (
                MerkleNode::Branch(Branch {
                    childs: values,
                    data: maybe_data,
                }),
                _rnode,
            ) => {
                changes.remove_node(&left_entry.value);
                changes.extend(&self.walk_branch(
                    Entry::new(left_entry.nibble, values),
                    maybe_data,
                    right_entry,
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

        changes
    }
    fn deep_op<FN>(&self, node: KeyedMerkleNode, ti: OpCollector<FN>) -> Changes
    where
        OpCollector<FN>: TrieInspector + Sync + Send,
    {
        let merkle_hashes = match node {
            KeyedMerkleNode::FullEncoded(hash, _) => vec![hash],
            KeyedMerkleNode::Partial(node) => {
                ReachableHashes::collect(&node, self.child_extractor.clone()).childs()
            }
        };

        let data_inspector = ChildCollector {
            child_hashes: Default::default(),
            child_extractor: self.child_extractor.clone(),
        };
        let walker = crate::walker::Walker::new_raw(self.db.borrow(), ti, data_inspector);
        let mut hashes_to_traverse = merkle_hashes;
        loop {
            for hash in hashes_to_traverse {
                walker.traverse(hash).unwrap()
            }

            hashes_to_traverse = std::mem::take(
                walker
                    .data_inspector
                    .child_hashes
                    .write()
                    .unwrap()
                    .deref_mut(),
            );
            if hashes_to_traverse.is_empty() {
                break;
            }
        }
        walker
            .trie_inspector
            .changes
            .into_inner()
            .expect("lock poisoned")
    }
    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn deep_insert(&self, node: KeyedMerkleNode) -> Changes {
        let collector = OpCollector::new(Change::Insert);
        self.deep_op(node, collector)
    }

    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn deep_remove(&self, node: KeyedMerkleNode) -> Changes {
        let collector = OpCollector::new(Change::Removal);
        self.deep_op(node, collector)
    }

    fn check_branch_level(left_slice: NibbleSlice, right_slice: NibbleSlice) -> ComparePathResult {
        let common = nibble::common(left_slice, right_slice);
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

    // Find branch for right_node and walk deeper into one of branch
    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn walk_branch(
        &self,
        left_entry: Entry<[MerkleValue; 16]>,
        maybe_data: Option<&[u8]>,
        right_entry: Entry<KeyedMerkleNode>,
    ) -> Changes {
        // Found a data in branch - it's a marker that key is not fixed sized.
        assert!(
            maybe_data.is_none(),
            "We support only fixed sized keys in diff"
        );

        let mut changes = Changes::default();

        let mut right_key = right_entry.nibble.clone();
        if let Some(rkey_suffix) = right_entry.value.merkle_node().nibbles() {
            right_key.extend_from_slice(&rkey_suffix)
        }

        let (_common, left_postfix, right_postfix) =
            nibble::common_with_sub(&left_entry.nibble, &right_key);
        assert!(
            left_postfix.is_empty(),
            "left tree should have smaller path in order to find changed node in branch."
        );
        let right_nibble = right_postfix[0]; // find first different nibble
        let r_index: usize = right_nibble.into();
        if let Some(conflict_branch) =
            <MerkleValue as MerkleValueExt>::node(&left_entry.value[r_index], self.db.borrow())
        {
            let conflict_key = {
                let mut lk = left_entry.nibble.clone();
                lk.push(right_nibble);
                lk
            };
            changes.extend(
                &self.compare_nodes(Entry::new(conflict_key, conflict_branch), right_entry),
            );
        } else {
            changes.extend(&self.deep_insert(right_entry.value))
        }

        for (index, value) in left_entry.value.iter().enumerate() {
            let branch_key = {
                let mut lk = left_entry.nibble.clone();
                lk.push(Nibble::from(index));
                lk
            };
            if let Some(branch) = value.node(self.db.borrow()) {
                // Compare changed nodes
                if right_nibble == Nibble::from(index) {
                    // Logic mooved before cycle ... conflict_branch
                    continue;
                } else {
                    // mark all remaining nodes as removed
                    changes.extend(&self.deep_remove(branch))
                }
            } else {
                log::trace!("Node {:?} was not found in branch", branch_key);
            }
        }
        changes
    }
}
static MERKLE_VALUE_EMPTY_EXT_ERR: &str = "Extension should never link to empty value";
