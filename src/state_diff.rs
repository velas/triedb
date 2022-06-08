use std::borrow::Borrow;
use std::ops::Deref;
use std::sync::RwLock;

use crate::Database;
use crate::gc::ReachableHashes;
use crate::merkle::nibble::{self, Nibble, NibbleSlice, NibbleVec};
use crate::merkle::{MerkleNode, MerkleValue};
use primitive_types::H256;
use rlp::Rlp;


use sha3::{Digest, Keccak256};
// use crate::rocksdb::OptimisticTransactionDB;
use rocksdb_lib::{ColumnFamily, MergeOperands, OptimisticTransactionDB};

#[cfg(feature="tracing-enable")]
use tracing::instrument;

#[derive(Debug)]
pub struct StateTraversal<DB> {
    pub db: DB,
    changeset: RwLock<Vec<u8>>,
}


fn tmp_no_child_extractor(data: &[u8]) -> Vec<H256>{
    log::error!("Replace with real child extractor");
    vec![]
}
#[derive(Debug, Clone)]
struct Cursor {
    nibble: NibbleVec,
    current_hash: H256,
}

#[derive(Debug, Clone)]
pub enum Change {
    Insert(H256, Vec<u8>),
    Removal(H256, Vec<u8>),
}

trait ChangeSetExt {
    fn remove_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a> >);
    fn insert_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a>>);
}
impl ChangeSetExt for Vec<Change> {
    fn remove_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a> >) {
        if let KeyedMerkleNode::FullEncoded(hash, data) = node.borrow() {
            self.push(Change::Removal(*hash, data.to_vec()))
        }else {
            log::trace!("Skipping to remove inline node")
        }
    }

    fn insert_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a>>){
        if let KeyedMerkleNode::FullEncoded(hash, data) = node.borrow() {
            self.push(Change::Insert(*hash, data.to_vec()))
        } else {
            log::trace!("Skipping to insert inline node")
        }
    }
}

trait MerkleValueExt<'a> {
    fn node(&self, database: &'a impl Database) -> Option<KeyedMerkleNode<'a>> ;
}
impl<'a> MerkleValueExt<'a> for MerkleValue<'a> {
    fn node(&self, database: &'a impl Database) -> Option<KeyedMerkleNode<'a>> {
        Some(match self {
            Self::Empty => return None,
            Self::Full(n) => KeyedMerkleNode::Partial(n.deref().clone()),
            Self::Hash(h) =>{
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
    FullEncoded(H256, &'a[u8]),
}


impl<'a> KeyedMerkleNode<'a> {
    fn same_hash(&self, other: &Self) -> bool {
        match (self, other) {
        (Self::FullEncoded(h, _),Self::FullEncoded(h2, _)) => h == h2,
        _ => false
        }
    }
    fn merkle_node(&self) -> MerkleNode {
        match self {
            Self::Partial(n) => n.clone(),
            Self::FullEncoded(_, n) =>  {
                let rlp = Rlp::new(n);
                MerkleNode::decode(&rlp).expect("Cannot deserialize value")
            }
        }
    }
}

impl<DB: Database + Send+ Sync> StateTraversal<DB> {
    pub fn new(db: DB, start_state_root: H256, end_state_root: H256) -> Self {
        StateTraversal {
            db,
            changeset: RwLock::new(Vec::new()),
        }
    }

    pub fn get_changeset(&self, start_state_root: H256, end_state_root: H256) -> Result<Vec<Change>, ()> {
        self.traverse_inner(
            Default::default(),
            Default::default(),
            start_state_root,
            end_state_root,
        )
    }

    fn traverse_inner(
        &self,
        left_nibble: NibbleVec,
        right_nibble: NibbleVec,
        left_tree_cursor: H256,
        right_tree_cursor: H256,
    ) -> Result<Vec<Change>, ()> {
        eprintln!("traversing left tree{:?} ...", left_tree_cursor);
        eprintln!("traversing rigth tree{:?} ...", right_tree_cursor);

        let db = &self.db;

        Ok(match (left_tree_cursor == crate::empty_trie_hash(), right_tree_cursor == crate::empty_trie_hash()) {
            (true, true) => {
                vec![]
            }
            (true, false) => {
                let bytes = db.get(right_tree_cursor);
                eprintln!("right raw bytes: {:?}", bytes);

                let right_node = KeyedMerkleNode::FullEncoded(right_tree_cursor, bytes);
                self.deep_insert(right_nibble, right_node)
            }
            (false, true) => {
                let bytes = db.get(left_tree_cursor);
                eprintln!("left raw bytes: {:?}", bytes);

                let left_node = KeyedMerkleNode::FullEncoded(left_tree_cursor, bytes);
                self.deep_remove(left_nibble, left_node)
            }
            (false, false) => {
                let bytes = db.get(left_tree_cursor);
                eprintln!("left raw bytes: {:?}", bytes);
                let left_node = KeyedMerkleNode::FullEncoded(left_tree_cursor, bytes);

                let bytes = db.get(right_tree_cursor);
                eprintln!("right raw bytes: {:?}", bytes);

                let right_node = KeyedMerkleNode::FullEncoded(right_tree_cursor, bytes);

                self.compare_nodes(left_nibble, left_node, right_nibble, right_node)
            }

        })
    }

    #[cfg_attr(feature="tracing-enable", instrument(skip(self)))]
    fn compare_nodes(
        &self,
        left_nibble: NibbleVec,
        left_node: KeyedMerkleNode,
        right_nibble: NibbleVec,
        right_node: KeyedMerkleNode,
    ) -> Vec<Change> {
        let mut changes = vec![];
        // TODO: check hash is enough there
        if left_node.same_hash(&right_node) {
            // if nodes are same - then left tree already contain this node - no reason to traverse it
            // return empty list
            return changes;
        }

        let branch_level = Self::check_branch_level(&left_nibble, &right_nibble);
        match dbg!(branch_level) {
            // We found two completely different paths
            ComparePathResult::Uncomparable => {
                changes.extend_from_slice(&self.deep_remove(left_nibble, left_node));
                changes.extend_from_slice(&self.deep_insert(right_nibble, right_node));
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

        match dbg!((left_node.merkle_node(), right_node.merkle_node())) {
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
                changes.remove_node(left_node);
                changes.insert_node(right_node)
            }
            // Leaf was replaced by subtree.
            (MerkleNode::Leaf(_lnibbles, ldata), rnode) => {
                changes.remove_node(left_node);
                changes.extend_from_slice(&self.deep_insert(right_nibble, right_node));
            }
            // We found extension at left part that differ from node from right.
            // Go deeper to find any branch or leaf.
            (MerkleNode::Extension(lnibbles, ldata), rnode) => {
                changes.remove_node(&left_node);
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
                for (idx, (left_value, right_value)) in lvalues.into_iter().zip(rvalues).enumerate() {
                    let b_nibble = {
                        let mut rn = right_nibble.clone();
                        rn.push(Nibble::from(idx));
                        rn
                    };
                    match (right_value.node(self.db.borrow()), left_value.node(self.db.borrow())) {
                        (Some(lnode), Some(rnode)) => changes.extend_from_slice(
                            &self.compare_nodes(b_nibble.clone(), lnode, b_nibble.clone(), rnode),
                        ),
                        (Some(lnode), None) => changes.remove_node(lnode),
                        (None, Some(rnode)) => changes.insert_node(rnode),
                        (None, None) => {}
                    }
                }
            }
            (MerkleNode::Branch(values, mb_data), rnode) => {
                changes.remove_node(&left_node);
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

    #[cfg_attr(feature="tracing-enable", instrument(skip(self)))]
    fn deep_insert(&self,
        nibble: NibbleVec,
        node: KeyedMerkleNode) -> Vec<Change> {

        let merkle_hashes = match node {
            KeyedMerkleNode::FullEncoded(hash, _) => vec![hash],
            KeyedMerkleNode::Partial(node) => {
                ReachableHashes::collect(&node, tmp_no_child_extractor).childs()
            }
        };
           
            
        struct InsertCollector {
            changes: RwLock<Vec<Change>>,
        };
        impl crate::walker::inspector::TrieInspector for InsertCollector {
            fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> anyhow::Result<bool > {
                self.changes.write().unwrap().push(Change::Insert(trie_key, node.as_ref().to_vec()));
                Ok(true)
            }
        }
        let collector = InsertCollector {
            changes: Default::default()
        };
        let walker = crate::walker::Walker::new_raw(self.db.borrow(), collector, crate::walker::inspector::NoopInspector);
        for hash in merkle_hashes {
            walker.traverse(hash).unwrap()
        }
        walker.trie_inspector.changes.into_inner().unwrap()
    }

    #[cfg_attr(feature="tracing-enable", instrument(skip(self)))]
    fn deep_remove(&self,
        nibble: NibbleVec,
        node: KeyedMerkleNode) -> Vec<Change> {


        let merkle_hashes = match node {
            KeyedMerkleNode::FullEncoded(hash, _) => vec![hash],
            KeyedMerkleNode::Partial(node) => {
                ReachableHashes::collect(&node, tmp_no_child_extractor).childs()
            }
        };
       
        
        struct RemoveCollector {
            changes: RwLock<Vec<Change>>,
        };
        impl crate::walker::inspector::TrieInspector for RemoveCollector {
            fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> anyhow::Result<bool > {
                self.changes.write().unwrap().push(Change::Removal(trie_key, node.as_ref().to_vec()));
                Ok(true)
            }
        }
        let collector = RemoveCollector {
            changes: Default::default()
        };
        let walker = crate::walker::Walker::new_raw(self.db.borrow(), collector, crate::walker::inspector::NoopInspector);
        for hash in merkle_hashes {
            walker.traverse(hash).unwrap()
        }
        walker.trie_inspector.changes.into_inner().unwrap()
    }

    #[cfg_attr(feature="tracing-enable", instrument)]
    fn reverse_changes(changes: Vec<Change>) -> Vec<Change> {
        changes.into_iter().map(|i|
        match i {
            Change::Insert(h, d) => Change::Removal(h, d),
            Change::Removal(h, d) => Change::Insert(h, d),
        }).collect()
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
    #[cfg_attr(feature="tracing-enable", instrument(skip(self)))]
    fn walk_branch(
        &self,
        left_nibble_prefix: NibbleVec,
        left_values: [MerkleValue; 16],
        mb_data: Option<&[u8]>,
        right_nibble: NibbleVec,
        right_node: KeyedMerkleNode,
    ) -> Vec<Change> {
        // Found a data in branch - it's a marker that key is not fixed sized.
        assert!(
            mb_data.is_none(),
            "We support only fixed sized keys in diff"
        );

        let mut changes = vec![];

        let mut right_nibble_with_postfix = right_nibble.clone();
        if let Some(rnibble_postfix) = right_node.merkle_node().nibble() {
            right_nibble_with_postfix.extend_from_slice(&rnibble_postfix)
        }

        let (common, left_postfix, right_postfix) =
            nibble::common_with_sub(&left_nibble_prefix, &right_nibble_with_postfix);
        assert!(
            left_postfix.is_empty(),
            "left tree should have smaller path in order to find changed node in branch."
        );
        let r_index = right_postfix[0]; // find first different nibble
        let r_index_usize: usize = r_index.into();
        if let Some(b_node) = <MerkleValue as MerkleValueExt>::node(&left_values[r_index_usize], self.db.borrow()) {
            let b_nibble = {
                let mut ln = left_nibble_prefix.clone();
                ln.push(r_index);
                ln
            };
            changes.extend_from_slice(&self.compare_nodes(
                b_nibble,
                b_node,
                right_nibble,
                right_node,
            ));
        } else {
            changes.extend_from_slice(&self.deep_insert(right_nibble,right_node))
        }

        for (index, value) in left_values.into_iter().enumerate() {
            let b_nibble = {
                let mut ln = left_nibble_prefix.clone();
                ln.push(Nibble::from(index));
                ln
            };
            if let Some(b_node) = value.node(self.db.borrow()) {
                // Compare changed nodes
                if r_index == Nibble::from(index) {
                    // Logic mooved before cycle
                    continue;
                } else {
                    // mark all remaining nodes as removed
                    changes.extend_from_slice(&self.deep_remove(b_nibble, b_node))
                }
            } else {
                log::trace!("Node {:?} was not found in branch", b_nibble);
            }
        }
        changes
    }

    // Walk deeper into extension
    #[cfg_attr(feature="tracing-enable", instrument(skip(self)))]
    fn walk_extension(
        &self,
        left_nibble: NibbleVec,
        left_value: MerkleValue,
        right_nibble: NibbleVec,
        right_node: KeyedMerkleNode,
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
    use std::cell::UnsafeCell;
    use std::collections::HashMap;
    use std::sync::Arc;

    use hex_literal::hex;
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::fmt::format::FmtSpan;

    use crate::CachedDatabaseHandle;
    use crate::gc::DbCounter;
    use crate::gc::MapWithCounter;
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

    // #[test]
    // fn test_two_same_leaves() {
    //     let key1 = &hex!("bbaa");
    //     let key2 = &hex!("ffaa");
    //     let key3 = &hex!("bbcc");

    //     // make data too long for inline
    //     let value1 = b"same data________________________";
    //     let value2 = b"same data________________________";
    //     let value3 = b"other data_______________________";
    //     let value3_1 = b"changed data_____________________";
    //     let value2_1 = b"changed data_____________________";

    //     let collection = TrieCollection::new(MapWithCounterCached::default());

    //     let mut trie = collection.trie_for(crate::empty_trie_hash());
    //     trie.insert(key1, value1);
    //     trie.insert(key2, value2);
    //     trie.insert(key3, value3);

    //     let patch = trie.into_patch();

    //     let st = StateTraversal::new(std::sync::Arc::new(trie), patch.root, patch.root);

    //     assert!(true)
    // }

    //
    // compare_nodes: (Remove(Extension('aaa')), compare_nodes(2))
    // compare_nodes: reverse(compare_nodes(3))
    // compare_nodes: (Remove(Branch('2['a','b']')), compare_nodes(4))
    // compare_nodes: (Remove(Extension('aa')), compare_nodes(5))
    // compare_nodes: same_node => {}
    // 'aaa' -> ['a', 'b']
    // extension -> branch 
    // ['a','b'] -> 'aa' -> ['a', 'b']
    // branch -> extension -> branch
    use crate::gc::testing::MapWithCounterCached;

    #[test]
    fn test_extension_replaced_by_branch_extension() {
        use tracing_subscriber;

        tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ENTER)
        .with_max_level(LevelFilter::TRACE).init();

        let key1 = &hex!("aaab");
        let key2 = &hex!("aaac");
        let key3 = &hex!("bbcc");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";
        let value3 = b"same data________________________";

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);

        let patch = trie.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie = collection.trie_for(first_root.root);

        trie.insert(key3, value3);
        let patch = trie.into_patch();

        let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = StateTraversal::new(&collection.database, first_root.root, last_root.root);
        log::info!("result change = {:?}", st.get_changeset(first_root.root, last_root.root).unwrap());
        drop(last_root);
        log::info!("second trie dropped")
    }
}
