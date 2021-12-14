use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use primitive_types::H256;
use rand::prelude::*;
use rocksdb_lib::{DB, Options, ColumnFamilyDescriptor};
use tempfile::tempdir;
use triedb::{MemoryTrieMut, TrieMut, rocksdb::{RocksHandle, RocksDatabaseHandle}, gc::TrieCollection};

const TEST_ENTRIES_AMOUNT: usize = 400;
const VALUE_SIZE_BYTES: usize = 1500;

#[cfg(target_family = "unix")]
const ROCKSDB_PATH: &'static str = "/tmp/rocksdb-bench";

#[cfg(target_family = "windows")]
const ROCKSDB_PATH: &'static str = r#"%TEMP%\rocksdb-bench"#;

fn deterministic_pseudorandom_data() -> Vec<(H256, [u8; VALUE_SIZE_BYTES])> {
    let mut rng = rand::rngs::StdRng::from_seed([42_u8; 32]);

    let mut ret = Vec::new();

    for _ in 0..TEST_ENTRIES_AMOUNT {
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

    ret
}

fn bench_db_backends(c: &mut Criterion) {
    let test_data = deterministic_pseudorandom_data();

    c.bench_function("bench HashMap", |b| {
        let mut sut = HashMap::new();
        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.insert(key, value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench DashMap", |b| {
        let sut = DashMap::new();
        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.insert(key, value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench RocksDB", |b| {
        let sut = DB::open_default(ROCKSDB_PATH).unwrap();
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
        use triedb::rocksdb::{DB, merge_counter};
        use triedb::empty_trie_hash;

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
        
        let handle = RocksDatabaseHandle::new(&db, cf);
        let handle2 = RocksHandle::new(handle);

        let collection = TrieCollection::new(handle2);

        
        b.iter_batched(
            ||
                (
                    collection.trie_for(empty_trie_hash()),
                    test_data.clone()
                ),
            |(mut trie, test_data)| {
                for (key, value) in test_data {
                    trie.insert(key.as_bytes(), &value);
                }
                
                let patch = trie.into_patch();
                let _root = collection.apply_increase(patch, |_| vec![]);
                // root_guards.push(RootGuard::new(&collection.database, root, vec![]));
            },
            criterion::BatchSize::SmallInput,
        );
    });

}

criterion_group!(benches, bench_db_backends);
criterion_main!(benches);
