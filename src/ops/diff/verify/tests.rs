use std::collections::{BTreeSet, HashMap, HashSet};

use crate::debug::child_extractor::DataWithRoot;
use crate::debug::{DebugPrintExt, MapWithCounterCached};
use crate::gc::tests::{FixedKey, RandomFixedData, VariableKey, RNG_DATA_SIZE};
use crate::mutable::TrieMut;
use crate::ops::diff::verify::VerificationError;
use crate::{debug, diff, empty_trie_hash, verify_diff, Database, DiffChange as Change};
use hex_literal::hex;
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};

use crate::gc::{RootGuard, TrieCollection};

use super::VerifiedPatch;

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

fn check_changes(
    changes: VerifiedPatch,
    initial_trie_data: &debug::EntriesHex,
    expected_trie_root: H256,
    expected_trie_data: debug::EntriesHex,
) {
    let collection = TrieCollection::new(MapWithCounterCached::default());
    let mut trie = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &initial_trie_data.data {
        trie.insert(key, value.as_ref().unwrap());
    }

    let patch = trie.into_patch();
    let _initial_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

    let apply_result = collection.apply_diff_patch(changes, no_childs);
    assert!(apply_result.is_ok());
    let expected_root_root_guard = apply_result.unwrap();
    assert_eq!(expected_root_root_guard.root, expected_trie_root);

    let new_trie = collection.trie_for(expected_trie_root);

    for (key, value) in expected_trie_data.data {
        assert_eq!(TrieMut::get(&new_trie, &key), value);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
struct VerifiedPatchHexStr {
    patch_dependencies: Option<BTreeSet<H256>>,
    sorted_changes: Vec<(H256, String)>,
}

impl From<VerifiedPatch> for VerifiedPatchHexStr {
    fn from(value: VerifiedPatch) -> Self {
        let mut result = Self {
            patch_dependencies: value.patch_dependencies,
            sorted_changes: Vec::new(),
        };
        for (hash, data) in value.sorted_changes.into_iter() {
            let ser = hexutil::to_hex(&data);
            result.sorted_changes.push((hash, ser));
        }

        log::info!("{}", serde_json::to_string_pretty(&result).unwrap());
        result
    }
}

fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
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

    let verify_result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

    let j = json!([
        ["0xaaab", null],
        [
            "0xaaac",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]
    ]);
    let expected_trie_data: debug::EntriesHex = serde_json::from_value(j).unwrap();
    check_changes(
        verify_result.unwrap(),
        &entries1,
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
    let verify_result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

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
        verify_result.unwrap(),
        &entries1,
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
    let verify_result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

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
        verify_result.unwrap(),
        &entries1,
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

    let verify_result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

    let diff_patch: VerifiedPatch = verify_result.unwrap();
    let diff_patch_ser: VerifiedPatchHexStr = diff_patch.clone().into();

    let j = json!({
        "patch_dependencies": [
            "0xcfb83f6df401062bbc6ec0e083bfdb1331c83162cb863272bea7c5d78805e25e"
        ],
        "sorted_changes": [
            [
                format!("{:?}", second_root.root),
                "0xe98710000000000000a0cfb83f6df401062bbc6ec0e083bfdb1331c83162cb863272bea7c5d78805e25e"
            ]
        ]
    });
    let exp_patch: VerifiedPatchHexStr = serde_json::from_value(j).unwrap();

    assert_eq!(diff_patch_ser, exp_patch);
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
    check_changes(diff_patch, &entries1, second_root.root, expected_trie_data);
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
    let verify_result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

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
        verify_result.unwrap(),
        &entries1,
        second_root.root,
        expected_trie_data,
    );
    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_5() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

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

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();

    // One entry removed which eliminates first branch node
    let j = json!([
        [
            "0xb0033333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
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

    let result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(result.is_ok());
    let diff_patch: VerifiedPatchHexStr = result.unwrap().into();

    let j = json!({
        "patch_dependencies": [
            "0xc905cc1f8c7992a69e8deabc075e6daf72029efa76b86be5e71903c0848001fb"
        ],
        "sorted_changes": [
            [
                format!("{:?}", second_root.root),
                "0xf871808080a09917c55a4ff0aea28a59174e0bf71ded54e14d0cfb345b7c4ebd50801363426980808080808080a0c905cc1f8c7992a69e8deabc075e6daf72029efa76b86be5e71903c0848001fb808080a04cf15526cbfe7ed0093e6e28346d9ef3977541a6b56fdea74a914df6b451e3d780"
            ],
            [
                "0x9917c55a4ff0aea28a59174e0bf71ded54e14d0cfb345b7c4ebd508013634269",
                "0xe583003333a0485d6a6f685291273df84688f4f884b68568f6c35f79037da41f020f6434e2db"
            ],
            [
                "0x4cf15526cbfe7ed0093e6e28346d9ef3977541a6b56fdea74a914df6b451e3d7",
                "0xe78433333333a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
            ],
            [
                "0x485d6a6f685291273df84688f4f884b68568f6c35f79037da41f020f6434e2db",
                "0xf851808080a0a1a9208173e3a50541f6961ca0eaede00a862a7d2bdad367c6122b1d9ec2117280808080808080a05bc0a795dae749afa7c4354e0b5cbb33e16e52c0c1da42bf02b5349ec554e8938080808080"
            ],
            [
                "0xa1a9208173e3a50541f6961ca0eaede00a862a7d2bdad367c6122b1d9ec21172",
                "0xe213a097eb90da8920ff6d6740f0bb8a89719d789a1fe6a871861eca5caba98d6f847b"
            ],
            [
                "0x5bc0a795dae749afa7c4354e0b5cbb33e16e52c0c1da42bf02b5349ec554e893",
                "0xe5822030a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
            ],
            [
                "0x97eb90da8920ff6d6740f0bb8a89719d789a1fe6a871861eca5caba98d6f847b",
                "0xf851808080a0999403f7e9f45fb8ccdc81134c04590524ece5ca8edcd9f884cb27208c6825de80808080808080a0999403f7e9f45fb8ccdc81134c04590524ece5ca8edcd9f884cb27208c6825de8080808080"
            ],
            [
                "0x999403f7e9f45fb8ccdc81134c04590524ece5ca8edcd9f884cb27208c6825de",
                "0xe320a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
            ],
            [
                "0x999403f7e9f45fb8ccdc81134c04590524ece5ca8edcd9f884cb27208c6825de",
                "0xe320a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
            ]
        ]
    });

    let exp_patch: VerifiedPatchHexStr = serde_json::from_value(j).unwrap();

    assert_eq!(diff_patch, exp_patch);

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_get_changeset_trivial_tree() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

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

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());

    debug::draw(
        &collection.database,
        debug::Child::Hash(empty_trie_hash()),
        vec![],
        no_childs,
    )
    .print();

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

    let changes = diff(
        &collection.database,
        no_childs,
        crate::empty_trie_hash(),
        first_root.root,
    )
    .unwrap();

    let result = verify_diff(
        &collection.database,
        first_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(result.is_ok());

    let diff_patch = result.unwrap();
    let diff_patch_ser: VerifiedPatchHexStr = diff_patch.clone().into();

    let j = json!({
        "patch_dependencies": [],
        "sorted_changes": [
            [
                format!("{:?}", first_root.root),
                "0xf871a0bbe6b76206a9cad7ef4b2c8a36b4c8e360c23363cd1db491126f9b245e2214e1808080808080a0bbe6b76206a9cad7ef4b2c8a36b4c8e360c23363cd1db491126f9b245e2214e1808080a0eda927899744a922998038fa648ddadb89500cee5938b4b533067c115e84fb3f8080808080"
            ],
            [
                "0xbbe6b76206a9cad7ef4b2c8a36b4c8e360c23363cd1db491126f9b245e2214e1",
                "0xe78430000000a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
            ],
            [
                "0xbbe6b76206a9cad7ef4b2c8a36b4c8e360c23363cd1db491126f9b245e2214e1",
                "0xe78430000000a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
            ],
            [
                "0xeda927899744a922998038fa648ddadb89500cee5938b4b533067c115e84fb3f",
                "0xe78430000000a15f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
            ]
        ]
    });

    let exp_patch: VerifiedPatchHexStr = serde_json::from_value(j).unwrap();

    assert_eq!(diff_patch_ser, exp_patch);

    for (hash, value) in diff_patch.sorted_changes {
        let actual_hash = H256::from_slice(Keccak256::digest(&value).as_slice());
        assert_eq!(hash, actual_hash);
    }
}

#[test]
fn test_leaf_node_and_extension_node() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

    let j = json!([[
        "0xaaab",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
    ]]);

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let j = json!([[
        "0xaaac",
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

    let changeset = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();

    let result = verify_diff(
        &collection.database,
        last_root.root,
        changeset,
        no_childs,
        true,
    );
    assert!(result.is_ok());

    let diff_patch: VerifiedPatchHexStr = result.unwrap().into();
    let j = json!({
      "patch_dependencies": [],
      "sorted_changes": [
        [
          format!("{:?}", last_root.root),
          "0xe4821aaaa040e05de038a539e7e53d1a02b4d583c0cedb256dec95f0f24025aa72f22bc047"
        ],
        [
          "0x40e05de038a539e7e53d1a02b4d583c0cedb256dec95f0f24025aa72f22bc047",
          "0xf8518080808080808080808080a0d0a649de60d406c5604edfe459e502accc44101096219256e324098fb00bb28da0d0a649de60d406c5604edfe459e502accc44101096219256e324098fb00bb28d80808080"
        ],
        [
          "0xd0a649de60d406c5604edfe459e502accc44101096219256e324098fb00bb28d",
          "0xe320a173616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ],
        [
          "0xd0a649de60d406c5604edfe459e502accc44101096219256e324098fb00bb28d",
          "0xe320a173616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ]
      ]
    });

    let exp_patch: VerifiedPatchHexStr = serde_json::from_value(j).unwrap();

    assert_eq!(diff_patch, exp_patch);
    drop(last_root);
    log::info!("second trie dropped")
}

fn split_changes(input: Vec<Change>) -> (HashSet<H256>, HashSet<H256>) {
    let mut removes = HashSet::<H256>::new();
    let mut inserts = HashSet::<H256>::new();
    for element in input {
        match element {
            Change::Insert(hash, _) => {
                log::trace!(
                    "====================== INSERT: {} ======================",
                    hash
                );
                inserts.insert(hash)
            }
            Change::Removal(hash, _) => {
                log::trace!(
                    "====================== REMOVE: {} ======================",
                    hash
                );
                removes.insert(hash)
            }
        };
    }
    (removes, inserts)
}

#[test]
fn test_diff_with_child_extractor() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

    let j = json!([
        [
            "0x00000000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0000000f",
            "0xee00000000000000000000000000000000000000000000000000000000000001"
        ],
        [
            "0x00000300",
            "0xff00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x00003000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0000f300",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0007f000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x000f0000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x03000000",
            "0x0100000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0f33ffff",
            "0x0100000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0xf0fff07f",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0xfffffff0",
            "0xee00000000000000000000000000000000000000000000000000000000000002"
        ],
        [
            "0xffffffff",
            "0xee00000000000000000000000000000000000000000000000000000000000003"
        ]
    ]);
    let entries1_1: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let j = json!([
        [
            "0x00000000",
            "0xff00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0000000f",
            "0xee00000000000000000000000000000000000000000000000000000000000010"
        ],
        [
            "0x00000300",
            "0xff00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x00000f33",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x00003000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0000f300",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0007f000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x000f0000",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x03000000",
            "0x0100000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0x0f33ffff",
            "0x0100000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0xf0fff07f",
            "0xee00000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "0xfffffff0",
            "0xee00000000000000000000000000000000000000000000000000000000000002"
        ],
        [
            "0xffffffff",
            "0xee00000000000000000000000000000000000000000000000000000000000003"
        ]
    ]);
    let entries1_2: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let j = json!([
        [
            "0x00000000",
            "0xee00000000000000000000000000000000000000000000000000000000000011"
        ],
        [
            "0x0007f000",
            "0xee00000000000000000000000000000000000000000000000000000000000012"
        ],
        [
            "0x03000000",
            "0x0100000000000000000000000000000000000000000000000000000000000111"
        ],
        [
            "0x00000fff",
            "0xff00000000000000000000000000000000000000000000000000000000000000"
        ]
    ]);
    let entries2_2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let keys1 = vec![(hexutil::read_hex("0x00000000").unwrap(), entries1_1)];
    let keys2 = vec![
        (hexutil::read_hex("0x00000000").unwrap(), entries1_2),
        (hexutil::read_hex("0x00000030").unwrap(), entries2_2),
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

    for (account_key, storage) in keys1.iter() {
        for (data_key, data) in &storage.data {
            {
                collection1_trie1 = debug::child_extractor::insert_element(
                    &collection1,
                    account_key,
                    data_key,
                    data.as_ref().unwrap(),
                    collection1_trie1.root,
                    DataWithRoot::get_childs,
                );
            }
            {
                collection2_trie1 = debug::child_extractor::insert_element(
                    &collection2,
                    account_key,
                    data_key,
                    data.as_ref().unwrap(),
                    collection2_trie1.root,
                    DataWithRoot::get_childs,
                );
            }
        }
    }

    debug::draw(
        &collection1.database,
        debug::Child::Hash(collection1_trie1.root),
        vec![],
        DataWithRoot::get_childs,
    )
    .print();

    let mut accounts_map: HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>> = HashMap::new();
    for (account_key, storage) in keys2.iter() {
        let account_updates = accounts_map.entry(account_key.clone()).or_default();
        for (data_key, data) in &storage.data {
            account_updates.insert(data_key.clone(), data.as_ref().unwrap().clone());
        }
    }

    for (account_key, storage) in keys2.iter() {
        for (data_key, data) in &storage.data {
            {
                collection1_trie2 = debug::child_extractor::insert_element(
                    &collection1,
                    account_key,
                    data_key,
                    data.as_ref().unwrap(),
                    collection1_trie2.root,
                    DataWithRoot::get_childs,
                );
            }
        }
    }

    debug::draw(
        &collection1.database,
        debug::Child::Hash(collection1_trie2.root),
        vec![],
        DataWithRoot::get_childs,
    )
    .print();

    let changes = diff(
        &collection1.database,
        DataWithRoot::get_childs,
        collection1_trie1.root,
        collection1_trie2.root,
    )
    .unwrap();

    let verify_result = verify_diff(
        &collection2.database,
        collection1_trie2.root,
        changes.clone(),
        DataWithRoot::get_childs,
        true,
    );
    assert!(verify_result.is_ok());

    let diff_patch: VerifiedPatch = verify_result.unwrap();
    let _diff_patch_serialized: VerifiedPatchHexStr = diff_patch.clone().into();
    let (removes, inserts) = split_changes(changes);
    let _common: HashSet<H256> = removes.intersection(&inserts).copied().collect();
    // TODO: uncomment
    // ERROR:
    // assert!(_common.is_empty());

    let apply_result = collection2.apply_diff_patch(diff_patch, DataWithRoot::get_childs);
    assert!(apply_result.is_ok());

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

#[test]
fn test_try_verify_invalid_changes() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    let collection1 = TrieCollection::new(MapWithCounterCached::default());
    let collection2 = TrieCollection::new(MapWithCounterCached::default());
    let j = json!([
        [
            "0xbbaa",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ],
        [
            "0xffaa",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ],
        [
            "0xbbcc",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ]
    ]);
    let entries: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let mut trie = collection1.trie_for(crate::empty_trie_hash());

    for (key, value) in &entries.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let root_guard = collection1.apply_increase(patch, no_childs);

    debug::draw(
        &collection1.database,
        debug::Child::Hash(root_guard.root),
        vec![],
        no_childs,
    )
    .print();

    log::info!("the only insertion {:?}", root_guard.root);
    let node = collection1.database.get(root_guard.root);
    let changes = vec![Change::Insert(root_guard.root, node.to_vec())];

    let result = verify_diff(
        &collection2.database,
        root_guard.root,
        changes,
        no_childs,
        true,
    );
    log::info!("{:?}", result);
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        crate::error::Error::Decoder(..) | crate::error::Error::DiffPatchApply(..) => {
            unreachable!()
        }
        crate::error::Error::Verification(verification_error) => {
            match verification_error {
                VerificationError::MissDependencyDB(hash) => {
                    assert_eq!(hash, H256::from_slice(&hexutil::read_hex("0x0a3d3e6b136f84355d29dadc750935a2dac1ea026245dd329fece4ad305e6613").unwrap()))
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn test_try_apply_diff_with_deleted_db_dependency() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

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

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();

    // One entry removed which eliminates first branch node
    let j = json!([
        [
            "0xb0033333",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
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
    let collection2 = TrieCollection::new(MapWithCounterCached::default());

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

    let mut trie2 = collection2.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let first_root2 = collection2.apply_increase(patch, crate::gc::tests::no_childs);

    let verify_result = verify_diff(
        &collection2.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

    // drop first root, that the patch is supposed to be based onto
    drop(first_root2);
    let apply_result = collection2.apply_diff_patch(verify_result.unwrap(), no_childs);
    assert!(apply_result.is_err());
    let err = unsafe {
        let err = apply_result.unwrap_err_unchecked();
        log::info!("{:?}", err);
        err
    };
    match err {
        crate::error::Error::Decoder(..) | crate::error::Error::Verification(..) => {
            unreachable!()
        }
        crate::error::Error::DiffPatchApply(hash) => {
            assert_eq!(
                hash,
                H256::from_slice(&hex!(
                    "c905cc1f8c7992a69e8deabc075e6daf72029efa76b86be5e71903c0848001fb"
                ))
            )
        }
    }

    drop(second_root);
    log::info!("second trie dropped")
}

use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult};

fn fixed_key_unique_random_data(values: HashSet<RandomFixedData>) -> debug::EntriesHex {
    let mut g = Gen::new(RNG_DATA_SIZE);
    let mut entries = vec![];
    for val in values.into_iter() {
        let key = FixedKey::arbitrary(&mut g);
        let entry = (key.0.to_vec(), Some(val.0.to_vec()));
        entries.push(entry);
    }

    debug::EntriesHex::new(entries)
}
fn variable_key_unique_random_data(values: HashSet<RandomFixedData>) -> debug::EntriesHex {
    let mut g = Gen::new(RNG_DATA_SIZE);
    let mut entries = vec![];
    for val in values.into_iter() {
        let key = VariableKey::arbitrary(&mut g);
        let entry = (key.0, Some(val.0.to_vec()));
        entries.push(entry);
    }

    debug::EntriesHex::new(entries)
}
fn join_entries(entries_1: &debug::EntriesHex, entries_2: &debug::EntriesHex) -> debug::EntriesHex {
    let mut join_map: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();
    for (key, val) in &entries_1.data {
        join_map.insert(key.clone(), val.clone());
    }

    for (key, val) in &entries_2.data {
        join_map.insert(key.clone(), val.clone());
    }
    let mut join_entries = vec![];
    for (key, val) in join_map.into_iter() {
        join_entries.push((key, val));
    }
    debug::EntriesHex::new(join_entries)
}

fn reverse_changes(changes: Vec<Change>) -> Vec<Change> {
    changes
        .into_iter()
        .map(|i| match i {
            Change::Insert(h, d) => Change::Removal(h, d),
            Change::Removal(h, d) => Change::Insert(h, d),
        })
        .collect()
}
fn empty_keys_union_diff_intersection_test_body(
    entries_1: debug::EntriesHex,
    entries_2: debug::EntriesHex,
) {
    let collection = TrieCollection::new(MapWithCounterCached::default());
    let collection_2 = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries_1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch.clone(), crate::gc::tests::no_childs);
    let _first_root = collection_2.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(first_root.root);
    for (key, value) in &entries_2.data {
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

    let (removes, inserts) = split_changes(changes.clone());

    let common: HashSet<H256> = removes.intersection(&inserts).copied().collect();
    assert!(common.is_empty());

    let verify_result = verify_diff(
        &collection_2.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(verify_result.is_ok());

    let apply_result = collection_2.apply_diff_patch(verify_result.unwrap(), no_childs);
    assert!(apply_result.is_ok());

    let new_trie = collection_2.trie_for(second_root.root);

    for (key, value) in &join_entries(&entries_1, &entries_2).data {
        assert_eq!(TrieMut::get(&new_trie, key), value.as_ref().cloned());
    }
}

fn empty_keys_distinct_diff_empty_intersection_and_reversal_test_body(
    entries_1: debug::EntriesHex,
    entries_2: debug::EntriesHex,
) {
    let collection = TrieCollection::new(MapWithCounterCached::default());
    let collection_reversal_target = TrieCollection::new(MapWithCounterCached::default());
    let collection_direct_target = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries_1.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch.clone(), crate::gc::tests::no_childs);
    let _first_root = collection_direct_target.apply_increase(patch, crate::gc::tests::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie2 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries_2.data {
        trie2.insert(key, value.as_ref().unwrap());
    }
    let patch = trie2.into_patch();
    let second_root = collection.apply_increase(patch.clone(), crate::gc::tests::no_childs);
    let _second_root =
        collection_reversal_target.apply_increase(patch, crate::gc::tests::no_childs);

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

    let (removes, inserts) = split_changes(changes.clone());

    let common: HashSet<H256> = removes.intersection(&inserts).copied().collect();
    assert!(common.is_empty());

    let reversed = reverse_changes(changes.clone());
    for (changes, collection, target_root, tested_entries) in [
        (
            changes,
            &collection_direct_target,
            second_root.root,
            &entries_2,
        ),
        (
            reversed,
            &collection_reversal_target,
            first_root.root,
            &entries_1,
        ),
    ] {
        let verify_result =
            verify_diff(&collection.database, target_root, changes, no_childs, true);
        assert!(verify_result.is_ok());

        let apply_result = collection.apply_diff_patch(verify_result.unwrap(), no_childs);
        assert!(apply_result.is_ok());

        let new_trie = collection.trie_for(target_root);

        // removing duplicates from tested_entries, checking for last value
        for (key, value) in &join_entries(tested_entries, tested_entries).data {
            assert_eq!(TrieMut::get(&new_trie, key), value.as_ref().cloned());
        }
    }
}

#[test]
fn qc_unique_nodes_fixed_key_empty_diff_intersection() {
    let _ = env_logger::Builder::new().parse_filters("error").try_init();
    fn property(keys_1: HashSet<RandomFixedData>, keys_2: HashSet<RandomFixedData>) -> TestResult {
        if keys_1.is_empty() || keys_2.is_empty() || keys_1 == keys_2 {
            return TestResult::discard();
        }
        let entries_1 = fixed_key_unique_random_data(keys_1);
        let entries_2 = fixed_key_unique_random_data(keys_2);
        empty_keys_union_diff_intersection_test_body(entries_1, entries_2);

        TestResult::passed()
    }
    QuickCheck::new()
        .gen(Gen::new(RNG_DATA_SIZE))
        // .tests(20_000)
        .quickcheck(
            property
                as fn(
                    keys_1: HashSet<RandomFixedData>,
                    keys_2: HashSet<RandomFixedData>,
                ) -> TestResult,
        );
}
#[test]
fn qc_unique_nodes_fixed_key_empty_diff_intersection_and_reversal() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    fn property(keys_1: HashSet<RandomFixedData>, keys_2: HashSet<RandomFixedData>) -> TestResult {
        if keys_1.is_empty() || keys_2.is_empty() || keys_1 == keys_2 {
            return TestResult::discard();
        }
        let entries_1 = fixed_key_unique_random_data(keys_1);
        let entries_2 = fixed_key_unique_random_data(keys_2);
        empty_keys_distinct_diff_empty_intersection_and_reversal_test_body(entries_1, entries_2);

        TestResult::passed()
    }
    QuickCheck::new()
        .gen(Gen::new(RNG_DATA_SIZE))
        // .tests(1000)
        .quickcheck(
            property
                as fn(
                    keys_1: HashSet<RandomFixedData>,
                    keys_2: HashSet<RandomFixedData>,
                ) -> TestResult,
        );
}

#[ignore = "Diff unimplemented for variable length keys"]
#[test]
fn qc_unique_nodes_variable_key_empty_diff_intersection_and_reversal() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    fn property(keys_1: HashSet<RandomFixedData>, keys_2: HashSet<RandomFixedData>) -> TestResult {
        if keys_1.is_empty() || keys_2.is_empty() || keys_1 == keys_2 {
            return TestResult::discard();
        }
        let entries_1 = variable_key_unique_random_data(keys_1);
        let entries_2 = variable_key_unique_random_data(keys_2);
        empty_keys_distinct_diff_empty_intersection_and_reversal_test_body(entries_1, entries_2);

        TestResult::passed()
    }
    QuickCheck::new()
        .gen(Gen::new(RNG_DATA_SIZE))
        .tests(1000)
        .quickcheck(
            property
                as fn(
                    keys_1: HashSet<RandomFixedData>,
                    keys_2: HashSet<RandomFixedData>,
                ) -> TestResult,
        );
}

#[ignore = "Diff unimplemented for variable length keys"]
#[test]
fn qc_unique_nodes_variable_key_empty_diff_intersection() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    fn property(keys_1: HashSet<RandomFixedData>, keys_2: HashSet<RandomFixedData>) -> TestResult {
        if keys_1.is_empty() || keys_2.is_empty() || keys_1 == keys_2 {
            return TestResult::discard();
        }
        let entries_1 = variable_key_unique_random_data(keys_1);
        let entries_2 = variable_key_unique_random_data(keys_2);
        empty_keys_union_diff_intersection_test_body(entries_1, entries_2);

        TestResult::passed()
    }
    QuickCheck::new()
        .gen(Gen::new(RNG_DATA_SIZE))
        // .tests(20_000)
        .quickcheck(
            property
                as fn(
                    keys_1: HashSet<RandomFixedData>,
                    keys_2: HashSet<RandomFixedData>,
                ) -> TestResult,
        );
}
