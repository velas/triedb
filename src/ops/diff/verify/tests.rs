use std::collections::BTreeSet;
use std::fs;

use crate::mutable::TrieMut;
use crate::{debug, diff, empty_trie_hash, verify_diff};
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::gc::testing::MapWithCounterCached;
use crate::gc::TrieCollection;

use super::VerifiedPatch;

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
        result
    }
}

fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}

static EXP_GET_CHANGESET_TRIVIAL_TREE_RESULT: &str = "./test_data/patch_changeset_trivial.json";
static EXP_GET_CHANGESET_TEST_3: &str = "./test_data/state_diff_test_3.json";
static EXP_GET_CHANGESET_TEST_5: &str = "./test_data/state_diff_test_5.json";

#[test]
fn test_3() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

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

    let result = verify_diff(
        &collection.database,
        second_root.root,
        changes,
        no_childs,
        true,
    );
    assert!(result.is_ok());

    let diff_patch: VerifiedPatchHexStr = result.unwrap().into();
    log::info!("{}", serde_json::to_string(&diff_patch).unwrap());

    let file = fs::read_to_string(EXP_GET_CHANGESET_TEST_3).expect("unable to read file");
    let exp_patch: VerifiedPatchHexStr = serde_json::from_str(&file).unwrap();

    assert_eq!(diff_patch, exp_patch);

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_5() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

    let keys1 = vec![
        (vec![176, 3, 51, 51], b"________________________________1"),
        (vec![51, 51, 48, 0], b"________________________________2"),
        (vec![3, 51, 51, 51], b"________________________________2"),
        (vec![51, 51, 59, 51], b"________________________________2"),
        (vec![51, 0, 0, 0], b"________________________________3"),
    ];
    // One entry removed which eliminates first branch node
    let keys2 = vec![
        (vec![176, 3, 51, 51], b"________________________________1"),
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

    let tree_display = debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    );
    println!("{}", tree_display);

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
    println!("{}", tree_display);

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
    log::info!("{}", serde_json::to_string(&diff_patch).unwrap());

    let file = fs::read_to_string(EXP_GET_CHANGESET_TEST_5).expect("unable to read file");
    let exp_patch: VerifiedPatchHexStr = serde_json::from_str(&file).unwrap();

    assert_eq!(diff_patch, exp_patch);

    drop(second_root);
    log::info!("second trie dropped")
}

#[test]
fn test_get_changeset_trivial_tree() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();

    let keys1 = vec![
        (vec![112, 0, 0, 0], b"________________________________2"),
        (vec![176, 0, 0, 0], b"________________________________1"),
        (vec![0, 0, 0, 0], b"________________________________1"),
        (vec![0, 0, 0, 0], b"________________________________2"),
    ];

    let collection = TrieCollection::new(MapWithCounterCached::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());

    let tree_display = debug::draw(
        &collection.database,
        debug::Child::Hash(empty_trie_hash()),
        vec![],
        no_childs,
    );
    log::info!("\n{}", tree_display);

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
    log::info!("{}", serde_json::to_string(&diff_patch_ser).unwrap());

    let file =
        fs::read_to_string(EXP_GET_CHANGESET_TRIVIAL_TREE_RESULT).expect("unable to read file");
    let exp_patch: VerifiedPatchHexStr = serde_json::from_str(&file).unwrap();

    assert_eq!(diff_patch_ser, exp_patch);

    for (hash, value) in diff_patch.sorted_changes {
        let actual_hash = H256::from_slice(Keccak256::digest(&value).as_slice());
        assert_eq!(hash, actual_hash);
    }
}
