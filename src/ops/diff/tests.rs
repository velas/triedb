use std::collections::HashMap;
use std::str::FromStr;

use hex_literal::hex;
use primitive_types::H256;
use rlp::Rlp;
use serde::{Deserialize, Serialize};

use crate::gc::TrieCollection;
use crate::gc::{DbCounter, RootGuard};
use crate::merkle::MerkleNode;
use crate::mutable::TrieMut;
use crate::{debug, diff, Database};

#[cfg(feature = "tracing-enable")]
fn tracing_sub_init() {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::fmt::format::FmtSpan;
    let _ = tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ENTER)
        .with_max_level(LevelFilter::TRACE)
        .try_init();
}
#[cfg(not(feature = "tracing-enable"))]
fn tracing_sub_init() {}

#[derive(Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DataWithRoot {
    pub root: H256,
}

impl DataWithRoot {
    fn get_childs(data: &[u8]) -> Vec<H256> {
        bincode::deserialize::<Self>(data)
            .ok()
            .into_iter()
            .map(|e| e.root)
            .collect()
    }
}
impl Default for DataWithRoot {
    fn default() -> Self {
        Self {
            root: crate::empty_trie_hash!(),
        }
    }
}

fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}

// compare_nodes: (Remove(Extension('aaa')), compare_nodes(2))
// compare_nodes: reverse(compare_nodes(3))
// compare_nodes: (Remove(Branch('2['a','b']')), compare_nodes(4))
// compare_nodes: (Remove(Extension('aa')), compare_nodes(5))
// compare_nodes: same_node => {}
// 'aaa' -> ['a', 'b']
// extension -> branch
// ['a','b'] -> 'aa' -> ['a', 'b']
// branch -> extension -> branch
use super::Change;
use crate::gc::testing::MapWithCounterCached;
fn check_changes(
    changes: &[Change],
    initial_trie_data: &Vec<(&[u8], &[u8])>,
    expected_trie_root: H256,
    expected_trie_data: &Vec<(&[u8], Option<Vec<u8>>)>,
) {
    let collection = TrieCollection::new(MapWithCounterCached::default());
    let mut trie = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in initial_trie_data {
        trie.insert(key, value);
    }
    let patch = trie.into_patch();
    let _initial_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    collection.apply_changes(changes.to_vec().into(), no_childs);

    let new_trie = collection.trie_for(expected_trie_root);
    for (key, value) in expected_trie_data {
        assert_eq!(TrieMut::get(&new_trie, key), *value);
    }
}

#[test]
fn test_extension_replaced_by_branch_extension() {
    tracing_sub_init();

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

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);

    let new_collection = TrieCollection::new(MapWithCounterCached::default());
    let mut trie = new_collection.trie_for(crate::empty_trie_hash());
    trie.insert(key1, value1);
    trie.insert(key2, value2);
    let patch = trie.into_patch();
    let _first_root = new_collection.apply_increase(patch, crate::gc::tests::no_childs);
    let changes = crate::Change {
        changes: changes
            .into_iter()
            .map(|change| match change {
                Change::Insert(key, val) => (key, Some(val)),
                Change::Removal(key, _) => (key, None),
            })
            .collect(),
    };
    for (key, value) in changes.changes.into_iter().rev() {
        if let Some(value) = value {
            log::info!("change(insert): key={}, value={:?}", key, value);
            new_collection
                .database
                .gc_insert_node(key, &value, crate::gc::tests::no_childs);
        }
    }

    let new_trie = new_collection.trie_for(last_root.root);
    assert_eq!(
        TrieMut::get(&new_trie, &hex!("bbcc")),
        Some(b"same data________________________".to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &hex!("aaab")),
        Some(b"same data________________________".to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &hex!("aaac")),
        Some(b"same data________________________".to_vec())
    );

    drop(last_root);
    log::info!("second trie dropped")
}

#[test]
fn test_two_empty_trees() {
    tracing_sub_init();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let trie = collection.trie_for(crate::empty_trie_hash());

    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let trie = collection.trie_for(first_root.root);
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);
    assert!(changes.is_empty());
    drop(last_root);
    log::info!("second trie dropped")
}

#[test]
fn test_empty_tree_and_leave() {
    tracing_sub_init();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    // Set up initial trie
    let trie = collection.trie_for(crate::empty_trie_hash());
    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    // Set up final trie
    let mut trie = collection.trie_for(first_root.root);
    trie.insert(&hex!("bbcc"), b"same data________________________");
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    // [Insert(0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7, [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95])];
    let key = H256::from_str("0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7")
        .unwrap();
    // let val1 = trie.get(key);
    let final_trie = collection.trie_for(last_root.root);
    let val1 = Database::get(&final_trie, key);
    dbg!("{:?}", val1);
    // let val1 = mutable::TrieMut::get(&final_trie, key);

    let val = vec![
        230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95,
        95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95,
    ];
    // H256::from_slice(&hex!("bbcc"));
    let expected_changeset = vec![Change::Insert(key, val)];

    let changeset = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    let insert = changeset.get(0).unwrap();
    let (k, raw_v) = match &insert {
        &Change::Insert(key, val) => Some((key, val)),
        _ => None,
    }
    .unwrap();

    let rlp = Rlp::new(raw_v);
    let v = MerkleNode::decode(&rlp).unwrap();

    dbg!(v);

    // Take a change from a second trie
    // Create a change for first tree out of it
    let mut changes = crate::Change {
        changes: vec![].into(),
    };
    let rrr = raw_v.clone();
    changes.add_raw(*k, rrr.to_vec());

    // Take previous version of a tree
    let new_collection = TrieCollection::new(MapWithCounterCached::default());
    // Process changes
    for (key, value) in changes.changes.into_iter().rev() {
        if let Some(value) = value {
            log::info!("change(insert): key={}, value={:?}", key, value);
            new_collection
                .database
                .gc_insert_node(key, &value, crate::gc::tests::no_childs);
        }
    }

    // compare trie
    let new_trie = new_collection.trie_for(last_root.root);
    assert_eq!(
        TrieMut::get(&new_trie, &hex!("bbcc")),
        Some(b"same data________________________".to_vec())
    );

    log::info!("result change = {:?}", changeset);
    log::info!("second trie dropped");
    assert_eq!(expected_changeset, changeset);

    // TrieCollection { database: AsyncCachedHandle { db: MapWithCounter { counter: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: 1}, data: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95]} }, cache: AsyncCache { cache: UnsafeCell { .. }, map: RwLock { data: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: 0}, poisoned: false, .. } } } }
    println!("{:?}", collection);
    // TrieCollection { database: AsyncCachedHandle { db: MapWithCounter { counter: {}, data: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95]} }, cache: AsyncCache { cache: UnsafeCell { .. }, map: RwLock { data: {}, poisoned: false, .. } } } }
    println!("{:?}", new_collection);
}

#[test]
fn test_leave_node_and_extension_node() {
    tracing_sub_init();

    let key1 = &hex!("aaab");
    let key2 = &hex!("aaac");

    // make data too long for inline
    let value1 = b"same data________________________";
    let value2 = b"same data________________________";

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie = collection.trie_for(crate::empty_trie_hash());
    trie.insert(key1, value1);

    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let mut trie = collection.trie_for(first_root.root);

    trie.insert(key2, value2);
    let patch = trie.into_patch();

    let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let changeset = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changeset);
    drop(last_root);
    log::info!("second trie dropped")
}

#[test]
fn test_two_different_leaf_nodes() {
    tracing_sub_init();

    let key1 = &hex!("aaab");
    let key2 = &hex!("aaac");

    // make data too long for inline
    let value1 = b"same data________________________1";
    let value2 = b"same data________________________2";

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    trie1.insert(key1, value1);
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    trie2.insert(key2, value2);
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);

    check_changes(
        &changes,
        &vec![(key1, value1)],
        second_root.root,
        &vec![
            (&hex!("aaab"), None),
            (
                &hex!("aaac"),
                Some(b"same data________________________2".to_vec()),
            ),
        ],
    );

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_1() {
    tracing_sub_init();

    let keys1 = vec![
        (
            vec![0, 0, 0, 0, 0, 0, 12, 25],
            b"________________________________1",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 203],
            b"________________________________2",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 16, 246],
            b"________________________________3",
        ),
    ];
    let keys2 = vec![
        (
            vec![0, 0, 0, 0, 0, 0, 13, 52],
            b"________________________________4",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 55],
            b"________________________________5",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 203],
            b"________________________________6",
        ),
    ];

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys1 {
        #[allow(clippy::explicit_auto_deref)]
        trie1.insert(key, *value);
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys2 {
        #[allow(clippy::explicit_auto_deref)]
        trie2.insert(key, *value);
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);

    check_changes(
        &changes,
        &keys1
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect(),
        second_root.root,
        &vec![
            (&[0, 0, 0, 0, 0, 0, 12, 25], None),
            (&[0, 0, 0, 0, 0, 0, 16, 246], None),
            (
                &[0, 0, 0, 0, 0, 0, 13, 52],
                Some(b"________________________________4".to_vec()),
            ),
            (
                &[0, 0, 0, 0, 0, 0, 15, 55],
                Some(b"________________________________5".to_vec()),
            ),
            (
                &[0, 0, 0, 0, 0, 0, 15, 203],
                Some(b"________________________________6".to_vec()),
            ),
        ],
    );

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_2() {
    tracing_sub_init();

    let keys1 = vec![
        (
            vec![0, 0, 0, 0, 0, 0, 12, 25],
            b"________________________________1",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 203],
            b"________________________________2",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 16, 246],
            b"________________________________3",
        ),
    ];
    let keys2 = vec![
        (
            vec![0, 0, 0, 0, 0, 0, 13, 52],
            b"________________________________4",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 203],
            b"________________________________5",
        ),
    ];

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys1 {
        #[allow(clippy::explicit_auto_deref)]
        trie1.insert(key, *value);
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys2 {
        #[allow(clippy::explicit_auto_deref)]
        trie2.insert(key, *value);
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);

    check_changes(
        &changes,
        &keys1
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect(),
        second_root.root,
        &vec![
            (&[0, 0, 0, 0, 0, 0, 12, 25], None),
            (&[0, 0, 0, 0, 0, 0, 16, 246], None),
            (
                &[0, 0, 0, 0, 0, 0, 13, 52],
                Some(b"________________________________4".to_vec()),
            ),
            (
                &[0, 0, 0, 0, 0, 0, 15, 203],
                Some(b"________________________________5".to_vec()),
            ),
        ],
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_3() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let keys1 = vec![
        (
            vec![0, 0, 0, 0, 0, 0, 12, 25],
            b"________________________________1",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 203],
            b"________________________________2",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 16, 246],
            b"________________________________3",
        ),
    ];
    // One entry removed which eliminates first branch node
    let keys2 = vec![
        (
            vec![0, 0, 0, 0, 0, 0, 12, 25],
            b"________________________________1",
        ),
        (
            vec![0, 0, 0, 0, 0, 0, 15, 203],
            b"________________________________2",
        ),
    ];

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys1 {
        #[allow(clippy::explicit_auto_deref)]
        trie1.insert(key, *value);
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let tree_display = debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    );
    log::info!("\n{}", tree_display);

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys2 {
        #[allow(clippy::explicit_auto_deref)]
        trie2.insert(key, *value);
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let tree_display = debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        no_childs,
    );
    log::info!("\n{}", tree_display);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();

    check_changes(
        &changes,
        &keys1
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect(),
        second_root.root,
        &vec![
            (&[0, 0, 0, 0, 0, 0, 16, 246], None),
            (
                &[0, 0, 0, 0, 0, 0, 12, 25],
                Some(b"________________________________1".to_vec()),
            ),
            (
                &[0, 0, 0, 0, 0, 0, 15, 203],
                Some(b"________________________________2".to_vec()),
            ),
        ],
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_4() {
    tracing_sub_init();

    let keys1 = vec![
        (vec![176, 3, 51, 51], b"________________________________1"),
        (vec![51, 51, 48, 0], b"________________________________2"),
        (vec![3, 51, 51, 51], b"________________________________2"),
        (vec![51, 51, 59, 51], b"________________________________2"),
        (vec![51, 0, 0, 0], b"________________________________3"),
    ];
    // One entry removed which eliminates first branch node
    let keys2 = vec![
        (vec![51, 51, 51, 51], b"________________________________2"),
        (vec![51, 51, 59, 48], b"________________________________2"),
        (vec![243, 51, 51, 51], b"________________________________2"),
        (vec![51, 51, 51, 51], b"________________________________1"),
        (vec![51, 51, 51, 59], b"________________________________1"),
    ];

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys1 {
        #[allow(clippy::explicit_auto_deref)]
        trie1.insert(key, *value);
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys2 {
        #[allow(clippy::explicit_auto_deref)]
        trie2.insert(key, *value);
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);

    check_changes(
        &changes,
        &keys1
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect(),
        second_root.root,
        &vec![
            (
                &[51, 51, 51, 51],
                Some(b"________________________________1".to_vec()),
            ),
            (
                &[51, 51, 59, 48],
                Some(b"________________________________2".to_vec()),
            ),
            (
                &[243, 51, 51, 51],
                Some(b"________________________________2".to_vec()),
            ),
            (
                &[51, 51, 51, 59],
                Some(b"________________________________1".to_vec()),
            ),
            (&[176, 3, 51, 51], None),
        ],
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_insert_by_existing_key() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let keys1 = vec![
        (vec![112, 0, 0, 0], b"________________________________2"),
        (vec![176, 0, 0, 0], b"________________________________1"),
        (vec![0, 0, 0, 0], b"________________________________1"),
        (vec![0, 0, 0, 0], b"________________________________2"),
    ];

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &keys1 {
        #[allow(clippy::explicit_auto_deref)]
        trie1.insert(key, *value);
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let tree_display = debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    );
    log::info!("\n{}", tree_display);

    let new_trie = collection.trie_for(first_root.root);
    assert_eq!(
        TrieMut::get(&new_trie, &[112, 0, 0, 0]),
        Some(b"________________________________2".to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &[176, 0, 0, 0]),
        Some(b"________________________________1".to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &[0, 0, 0, 0]),
        Some(b"________________________________2".to_vec())
    );
}

#[test]
fn test_diff_with_child_extractor() {
    tracing_sub_init();

    let keys1 = vec![(
        vec![0, 0, 0, 0],
        vec![
            (
                vec![0, 0, 0, 0],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![0, 0, 0, 15],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![0, 0, 3, 0],
                vec![
                    255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![0, 0, 48, 0],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![0, 0, 243, 0],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![0, 7, 240, 0],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![0, 15, 0, 0],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![3, 0, 0, 0],
                vec![
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![15, 51, 255, 255],
                vec![
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![240, 255, 240, 127],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![255, 255, 255, 240],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                vec![255, 255, 255, 255],
                vec![
                    238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ],
    )];

    let keys2 = vec![
        (
            vec![0, 0, 0, 0],
            vec![
                (
                    vec![0, 0, 0, 0],
                    vec![
                        255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 0, 15],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 3, 0],
                    vec![
                        255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 15, 51],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 48, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 243, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 7, 240, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 15, 0, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![3, 0, 0, 0],
                    vec![
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![15, 51, 255, 255],
                    vec![
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![240, 255, 240, 127],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![255, 255, 255, 240],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![255, 255, 255, 255],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ],
        ),
        (
            vec![0, 0, 0, 48],
            vec![
                (
                    vec![0, 0, 0, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 7, 240, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![3, 0, 0, 0],
                    vec![
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 15, 255],
                    vec![
                        255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ],
        ),
    ];

    let collection1 = TrieCollection::new(MapWithCounterCached::default());
    let collection2 = TrieCollection::new(MapWithCounterCached::default());
    let mut collection1_trie1 = RootGuard::new(
        &collection1.database,
        crate::empty_trie_hash(),
        DataWithRoot::get_childs,
    );
    let mut collection1_trie2 = RootGuard::new(
        &collection1.database,
        crate::empty_trie_hash(),
        DataWithRoot::get_childs,
    );
    let mut collection2_trie1 = RootGuard::new(
        &collection2.database,
        crate::empty_trie_hash(),
        DataWithRoot::get_childs,
    );

    for (k, storage) in keys1.iter() {
        for (data_key, data) in storage {
            {
                // Insert to first db
                let mut account_trie = collection1.trie_for(collection1_trie1.root);
                let mut account: DataWithRoot = TrieMut::get(&account_trie, k)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();
                let mut storage_trie = collection1.trie_for(account.root);
                storage_trie.insert(data_key, data);
                let storage_patch = storage_trie.into_patch();
                log::trace!(
                    "1 Update account root: old {}, new {}",
                    account.root,
                    storage_patch.root
                );
                account.root = storage_patch.root;
                account_trie.insert(k, &bincode::serialize(&account).unwrap());
                let mut account_patch = account_trie.into_patch();
                account_patch.change.merge_child(&storage_patch.change);

                collection1_trie1 =
                    collection1.apply_increase(account_patch, DataWithRoot::get_childs);
            }
            {
                // Insert to second db
                let mut account_trie = collection2.trie_for(collection2_trie1.root);
                let mut account: DataWithRoot = TrieMut::get(&account_trie, k)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();
                let mut storage_trie = collection2.trie_for(account.root);
                storage_trie.insert(data_key, data);
                let storage_patch = storage_trie.into_patch();
                account.root = storage_patch.root;
                account_trie.insert(k, &bincode::serialize(&account).unwrap());
                let mut account_patch = account_trie.into_patch();
                account_patch.change.merge_child(&storage_patch.change);

                collection2_trie1 =
                    collection2.apply_increase(account_patch, DataWithRoot::get_childs);
            }
        }
    }

    let mut accounts_map: HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>> = HashMap::new();
    for (k, storage) in keys2.iter() {
        let account_updates = accounts_map.entry(k.clone()).or_default();
        for (data_key, data) in storage {
            let mut account_trie = collection1.trie_for(collection1_trie2.root);
            let mut account: DataWithRoot = TrieMut::get(&account_trie, k)
                .map(|d| bincode::deserialize(&d).unwrap())
                .unwrap_or_default();
            let mut storage_trie = collection1.trie_for(account.root);
            account_updates.insert(data_key.clone(), data.clone());
            storage_trie.insert(data_key, data);
            let storage_patch = storage_trie.into_patch();
            log::trace!(
                "2 Update account root: old {}, new {}",
                account.root,
                storage_patch.root
            );
            account.root = storage_patch.root;
            account_trie.insert(k, &bincode::serialize(&account).unwrap());
            let mut account_patch = account_trie.into_patch();
            account_patch.change.merge_child(&storage_patch.change);

            collection1_trie2 = collection1.apply_increase(account_patch, DataWithRoot::get_childs);
        }
    }

    let changes = diff(
        &collection1.database,
        DataWithRoot::get_childs,
        collection1_trie1.root,
        collection1_trie2.root,
    )
    .unwrap();
    log::info!("result change = {:?}", changes);
    let changes = crate::Change {
        changes: changes
            .into_iter()
            .map(|change| match change {
                Change::Insert(key, val) => {
                    println!(
                        "====================== INSERT: {} ======================",
                        key
                    );
                    (key, Some(val))
                }
                Change::Removal(key, _) => {
                    println!(
                        "====================== REMOVE: {} ======================",
                        key
                    );
                    (key, None)
                }
            })
            .collect(),
    };

    for (key, value) in changes.changes.into_iter().rev() {
        if let Some(value) = value {
            collection2
                .database
                .gc_insert_node(key, &value, DataWithRoot::get_childs);
        }
    }

    let accounts_storage = collection2.trie_for(collection1_trie2.root);
    for (k, storage) in accounts_map {
        let account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &k).unwrap()).unwrap();

        let account_storage_trie = collection2.trie_for(account.root);
        for data_key in storage.keys() {
            assert_eq!(
                &storage[data_key][..],
                &TrieMut::get(&account_storage_trie, data_key).unwrap()
            );
        }
    }
}
