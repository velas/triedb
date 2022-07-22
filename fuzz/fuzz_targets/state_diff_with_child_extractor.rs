#![no_main]

use arbitrary::{Arbitrary, Error, Result, Unstructured};
use libfuzzer_sys::{arbitrary, fuzz_target};

#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct Key(pub [u8; 4]);
#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct FixedData(pub [u8; 32]);

use primitive_types::H256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use triedb::empty_trie_hash;
use triedb::gc::{DbCounter, RootGuard, TrieCollection};
use triedb::gc::testing::MapWithCounterCached;
use triedb::merkle::nibble::{into_key, Nibble};
use triedb::state_diff::{Change, DiffFinder};
use triedb::TrieMut;


impl<'a> Arbitrary<'a> for Key {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // Get an iterator of arbitrary `T`s.
        let nibble: Result<Vec<_>> = std::iter::from_fn(|| {
            Some(
                u.choose(&[Nibble::N0, Nibble::N3, Nibble::N7, Nibble::N11, Nibble::N15])
                    .map(|c| *c),
            )
        })
            .take(8)
            .collect();
        let mut key = [0; 4];

        let vec_data = into_key(&nibble?);
        assert_eq!(key.len(), vec_data.len());
        key.copy_from_slice(&vec_data);

        Ok(Key(key))
    }
}

impl<'a> Arbitrary<'a> for FixedData {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut fixed = [0; 32]; // increase possibility of conflict.

        fixed[0] = *u.choose(&[0xff, 0x01, 0x00, 0xee])?;

        Ok(FixedData(fixed))
    }
}

#[derive(Debug)]
pub struct MyArgs {
    changes: Vec<(Key, Vec<(Key, FixedData)>)>,

    changes2: Vec<(Key, Vec<(Key, FixedData)>)>,
}

impl<'a> Arbitrary<'a> for MyArgs {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let changes: Vec<(Key, Vec<(Key, FixedData)>)> = u.arbitrary()?;
        if changes.len() < 5 {
            return Err(Error::NotEnoughData);
        }
        for change in &changes {
            if change.1.len() < 5 {
                return Err(Error::NotEnoughData);
            }
        }

        let changes2: Vec<(Key, Vec<(Key, FixedData)>)> = u.arbitrary()?;
        if changes2.len() < 5 {
            return Err(Error::NotEnoughData);
        }
        for change in &changes2 {
            if change.1.len() < 5 {
                return Err(Error::NotEnoughData);
            }
        }

        Ok(MyArgs { changes, changes2 })
    }
}

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
            root: empty_trie_hash!(),
        }
    }
}

fn test_state_diff(
    changes: Vec<(Key, Vec<(Key, FixedData)>)>,
    changes2: Vec<(Key, Vec<(Key, FixedData)>)>,
) {
    let _ = env_logger::Builder::new().parse_filters("trace").try_init();
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

    // Insert first trie into collections
    for (k, storage) in changes.iter() {
        for (data_key, data) in storage {
            {
                // Create patch with account and storage changes
                let mut account_trie = collection1.trie_for(collection1_trie1.root);
                let mut account: DataWithRoot = TrieMut::get(&account_trie, &k.0)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();
                let mut storage_trie = collection1.trie_for(account.root);
                storage_trie.insert(&data_key.0, &data.0);
                let storage_patch = storage_trie.into_patch();
                account.root = storage_patch.root;
                account_trie.insert(&k.0, &bincode::serialize(&account).unwrap());
                let mut account_patch = account_trie.into_patch();
                account_patch.change.merge_child(&storage_patch.change);

                // Apply patch over two collections
                collection1_trie1 = collection1.apply_increase(account_patch.clone(), DataWithRoot::get_childs);
                collection2_trie1 = collection2.apply_increase(account_patch, DataWithRoot::get_childs);
            }
        }
    }

    // Insert second trie into first collection and into HashMap to be able to check results
    let mut accounts_map: HashMap<Key, HashMap<Key, FixedData>> = HashMap::new();
    for (k, storage) in changes2.iter() {
        let account_updates = accounts_map.entry(*k).or_insert(HashMap::default());

        for (data_key, data) in storage {
            let mut account_trie = collection1.trie_for(collection1_trie2.root);
            let mut account: DataWithRoot = TrieMut::get(&account_trie, &k.0)
                .map(|d| bincode::deserialize(&d).unwrap())
                .unwrap_or_default();
            let mut storage_trie = collection1.trie_for(account.root);
            account_updates.insert(*data_key, *data);
            storage_trie.insert(&data_key.0, &data.0);
            let storage_patch = storage_trie.into_patch();
            account.root = storage_patch.root;
            account_trie.insert(&k.0, &bincode::serialize(&account).unwrap());
            let mut account_patch = account_trie.into_patch();
            account_patch.change.merge_child(&storage_patch.change);

            collection1_trie2 = collection1.apply_increase(account_patch, DataWithRoot::get_childs);
        }
    }

    // Get diff between two tries in the first collection
    let st = DiffFinder::new(&collection1.database, collection1_trie1.root, collection1_trie2.root, DataWithRoot::get_childs);
    let changes = st.get_changeset(collection1_trie1.root, collection1_trie2.root).unwrap();
    let changes = triedb::Change {
        changes: changes.clone().into_iter().map(|change| {
            match change {
                Change::Insert(key, val) => {
                    (key, Some(val))
                },
                Change::Removal(key, _) => {
                    (key, None)
                },
            }
        }).collect()
    };
    // Apply changes over the initial trie in the second collection
    collection2.apply_changes(changes, DataWithRoot::get_childs);

    // Compare contents of HashMap and final trie in the second collection
    let accounts_storage = collection2.trie_for(collection1_trie2.root);
    for (k, storage) in accounts_map {
        let account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &k.0).unwrap()).unwrap();

        let account_storage_trie = collection2.trie_for(account.root);
        for data_key in storage.keys() {
            assert_eq!(
                &storage[data_key].0[..],
                &TrieMut::get(&account_storage_trie, &data_key.0).unwrap()
            );
        }
    }
}

fuzz_target!(|arg: MyArgs| { test_state_diff(arg.changes, arg.changes2) });