use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use primitive_types::H256;
use rand::prelude::*;
use rocksdb_lib::{DB, Options};
use triedb::{MemoryTrieMut, TrieMut};

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

    let mut sut = HashMap::new();
    c.bench_function("bench HashMap", |b| {
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

    let sut = DashMap::new();
    c.bench_function("bench DashMap", |b| {
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

    let sut = DB::open_default(ROCKSDB_PATH).unwrap();
    c.bench_function("bench RocksDB", |b| {
        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.put(key, value).unwrap();
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });
    drop(sut);
    DB::destroy(&Options::default(), ROCKSDB_PATH).unwrap();

    let mut sut = MemoryTrieMut::default();
    c.bench_function("bench MemoryTrieMut", |b| {
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
}

criterion_group!(benches, bench_db_backends);
criterion_main!(benches);
