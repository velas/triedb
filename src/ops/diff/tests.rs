use std::str::FromStr;

use primitive_types::H256;
use rlp::Rlp;
use serde_json::json;

use crate::debug::DebugPrintExt;
use crate::gc::DbCounter;
use crate::gc::TrieCollection;
use crate::merkle::MerkleNode;
use crate::mutable::TrieMut;
use crate::{debug, diff};

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
    expected_trie_data: debug::EntriesHex,
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

    for (key, value) in expected_trie_data.data {
        assert_eq!(TrieMut::get(&new_trie, &key), value);
    }
}

#[test]
fn test_extension_replaced_by_branch_extension() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0xaaab",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ],
        [
            "0xaaac",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ]
    ]);

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let j = json!([[
        "0xbbcc",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
    ]]);

    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie = collection.trie_for(crate::empty_trie_hash());

    for (key, value) in &entries1.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);
    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie = collection.trie_for(first_root.root);
    for (key, value) in &entries2.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(last_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    log::info!("result change = {:#?}", changes);

    let new_collection = TrieCollection::new(MapWithCounterCached::default());
    let mut trie = new_collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie.insert(key, value.as_ref().unwrap());
    }
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
    // ERROR: order is _ucked up
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
        TrieMut::get(&new_trie, &entries2.data[0].0),
        entries2.data[0].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries1.data[0].0),
        entries1.data[0].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries1.data[1].0),
        entries1.data[1].1.as_ref().map(|val| val.to_vec())
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
    assert!(changes.is_empty());
    drop(last_root);
    log::info!("second trie dropped")
}

#[test]
fn test_empty_tree_and_leaf() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    // Set up initial trie
    let trie = collection.trie_for(crate::empty_trie_hash());
    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    // Set up final trie
    let mut trie = collection.trie_for(first_root.root);

    let j = json!([[
        "0xbbcc",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
    ]]);

    let entries: debug::EntriesHex = serde_json::from_value(j).unwrap();

    for (key, value) in &entries.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(last_root.root),
        vec![],
        no_childs,
    )
    .print();

    // [Insert(0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7, [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95])];
    let key = H256::from_str("0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7")
        .unwrap();

    let val = hexutil::read_hex(
        "0xe68320bbcca173616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f",
    )
    .unwrap();

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

    log::info!("{:?}", v);

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
        TrieMut::get(&new_trie, &entries.data[0].0),
        entries.data[0].1
    );

    log::info!("result change = {:?}", changeset);
    log::info!("second trie dropped");
    assert_eq!(expected_changeset, changeset);
}

#[test]
fn test_two_different_leaf_nodes() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([[
        "0xaaab",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
    ]]);
    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();

    // make data too long for inline
    let j = json!([[
        "0xaaac",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
    ]]);
    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries2.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();

    let j = json!([
        ["0xaaab", null],
        [
            "0xaaac",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]
    ]);
    let expected_trie_data: debug::EntriesHex = serde_json::from_value(j).unwrap();
    check_changes(
        &changes,
        &entries1
            .data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_ref().unwrap().as_slice()))
            .collect(),
        second_root.root,
        expected_trie_data,
    );

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_1() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0x0000000000000c19",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x00000000000010f6",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f33"
        ]
    ]);

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let j = json!([
        [
            "0x0000000000000d34",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f34"
        ],
        [
            "0x0000000000000f37",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f35"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f36"
        ]
    ]);
    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries2.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();

    let j = json!([
        ["0x0000000000000c19", null],
        ["0x00000000000010f6", null],
        [
            "0x0000000000000d34",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f34"
        ],
        [
            "0x0000000000000f37",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f35"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f36"
        ]
    ]);

    let expected_trie_data: debug::EntriesHex = serde_json::from_value(j).unwrap();
    check_changes(
        &changes,
        &entries1
            .data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_ref().unwrap().as_slice()))
            .collect(),
        second_root.root,
        expected_trie_data,
    );

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_2() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0x0000000000000c19",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x00000000000010f6",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f33"
        ]
    ]);

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let j = json!([
        [
            "0x0000000000000d34",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f34"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f35"
        ]
    ]);

    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries2.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();

    let j = json!([
        ["0x0000000000000c19", null],
        ["0x00000000000010f6", null],
        [
            "0x0000000000000d34",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f34"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f35"
        ]
    ]);
    let expected_trie_data: debug::EntriesHex = serde_json::from_value(j).unwrap();
    check_changes(
        &changes,
        &entries1
            .data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_ref().unwrap().as_slice()))
            .collect(),
        second_root.root,
        expected_trie_data,
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_3() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0x0000000000000c19",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x00000000000010f6",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f33"
        ]
    ]);

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();

    // One entry removed which eliminates first branch node
    let j = json!([
        [
            "0x0000000000000c19",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]
    ]);
    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries2.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    let j = json!([
        ["0x00000000000010f6", null],
        [
            "0x0000000000000c19",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x0000000000000fcb",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]
    ]);

    let expected_trie_data: debug::EntriesHex = serde_json::from_value(j).unwrap();
    check_changes(
        &changes,
        &entries1
            .data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_ref().unwrap().as_slice()))
            .collect(),
        second_root.root,
        expected_trie_data,
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_4() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0xb0033333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x33333000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x03333333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x33333b33",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x33000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f33"
        ]
    ]);

    // One entry removed which eliminates first branch node

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let j = json!([
        [
            "0x33333333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x33333b30",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0xf3333333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x33333333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x3333333b",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ]
    ]);

    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries2.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        second_root.root,
    )
    .unwrap();

    let j = json!([
        [
            "0x33333333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x33333b30",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0xf3333333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x3333333b",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        ["0xb0033333", null]
    ]);

    let expected_trie_data: debug::EntriesHex = serde_json::from_value(j).unwrap();
    check_changes(
        &changes,
        &entries1
            .data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_ref().unwrap().as_slice()))
            .collect(),
        second_root.root,
        expected_trie_data,
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_insert_by_existing_key() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0x70000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0xb0000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x00000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x00000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]
    ]);
    let entries: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let new_trie = collection.trie_for(first_root.root);
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[0].0),
        entries.data[0].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[1].0),
        entries.data[1].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[3].0),
        entries.data[3].1.as_ref().map(|val| val.to_vec())
    );
}
