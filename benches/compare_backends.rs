use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use primitive_types::H256;
use rand::prelude::*;
use rocksdb_lib::{ColumnFamilyDescriptor, Options, DB};
use tempfile::tempdir;
use triedb::{
    gc::TrieCollection,
    rocksdb::{RocksDatabaseHandle, RocksHandle},
    MemoryTrieMut, TrieMut,
};

// Amount of entries to be added to collection before benching
const PREP_SIZE: usize = 400;
const PREP_SEED: [u8; 32] = [57_u8; 32];

// Amount of entries to be added to collection during benching
const BENCH_AMOUNT: usize = 400;
const BENCH_SEED: [u8; 32] = [42_u8; 32];

const VALUE_SIZE_BYTES: usize = 1500;

#[cfg(target_family = "unix")]
const ROCKSDB_PATH: &'static str = "/tmp/rocksdb-bench";

#[cfg(target_family = "windows")]
const ROCKSDB_PATH: &'static str = r#"%TEMP%\rocksdb-bench"#;

fn rand_collection(
    seed: [u8; 32],
    size: usize,
) -> impl Iterator<Item = (H256, [u8; VALUE_SIZE_BYTES])> {
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let mut ret = Vec::with_capacity(size);

    for _ in 0..size {
        let key = {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            H256(key)
        };

        let value = {
            let mut value = [0u8; VALUE_SIZE_BYTES];
            rng.fill_bytes(&mut value);
            value
        };

        ret.push((key, value));
    }

    ret.into_iter()
}

fn bench_db_backends(c: &mut Criterion) {
    let test_data: Vec<_> = rand_collection(BENCH_SEED, BENCH_AMOUNT).collect();

    c.bench_function("bench HashMap", |b| {
        b.iter_batched(
            || {
                (
                    test_data.clone(),
                    rand_collection(PREP_SEED, PREP_SIZE).collect::<HashMap<_, _>>(),
                )
            },
            |(test_data, mut sut)| {
                for (key, value) in test_data {
                    sut.insert(key, value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench DashMap", |b| {
        b.iter_batched(
            || {
                (
                    test_data.clone(),
                    rand_collection(PREP_SEED, PREP_SIZE).collect::<DashMap<_, _>>(),
                )
            },
            |(test_data, sut)| {
                for (key, value) in test_data {
                    sut.insert(key, value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench RocksDB", |b| {
        let sut = DB::open_default(ROCKSDB_PATH).unwrap();

        let prep: Vec<_> = rand_collection(PREP_SEED, PREP_SIZE).collect();

        for (key, value) in prep {
            sut.put(key, value).unwrap();
        }

        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.put(key, value).unwrap();
                }
            },
            criterion::BatchSize::SmallInput,
        );
        drop(sut);
        DB::destroy(&Options::default(), ROCKSDB_PATH).unwrap();
    });

    c.bench_function("bench MemoryTrieMut", |b| {
        let mut sut = MemoryTrieMut::default();

        let prep: Vec<_> = rand_collection(PREP_SEED, PREP_SIZE).collect();

        for (key, value) in prep {
            sut.insert(key.as_bytes(), &value);
        }

        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.insert(key.as_bytes(), &value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench TrieCollection", |b| {
        use triedb::empty_trie_hash;
        use triedb::rocksdb::{merge_counter, DB};

        fn default_opts() -> Options {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            opts
        }

        fn counter_cf_opts() -> Options {
            let mut opts = default_opts();
            opts.set_merge_operator_associative("inc_counter", merge_counter);
            opts
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let handle = RocksHandle::new(RocksDatabaseHandle::new(&db, cf));

        let collection = TrieCollection::new(handle);

        b.iter_batched(
            || {
                let prep: Vec<_> = rand_collection(PREP_SEED, PREP_SIZE).collect();
                let mut trie = collection.trie_for(empty_trie_hash());

                for (key, value) in prep {
                    trie.insert(key.as_bytes(), &value);
                }

                (test_data.clone(), trie)
            },
            |(test_data, mut trie)| {
                for (key, value) in test_data {
                    trie.insert(key.as_bytes(), &value);
                }

                let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
                let _root = collection.apply_increase(patch, |_| vec![]);
                // root_guards.push(RootGuard::new(&collection.database, root, vec![]));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_db_backends);
criterion_main!(benches);
