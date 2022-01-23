// trace_macros!(true);
use std::{collections::HashMap, time::Duration, time::Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use primitive_types::H256;
use rand::prelude::*;
use rocksdb_lib::{ColumnFamilyDescriptor, OptimisticTransactionDB, Options};
use tempfile::tempdir;
use triedb::{
    gc::TrieCollection,
    rocksdb::{RocksDatabaseHandle, RocksHandle},
    MemoryTrieMut, TrieMut,
};
type DB = OptimisticTransactionDB;

// Amount of entries to be added to collection before benching
const PREP_SIZE: usize = 1000;
const PREP_SEED: [u8; 32] = [57_u8; 32];

// Amount of entries to be added to collection during benching
const BENCH_AMOUNT: usize = 200;
const BENCH_SEED: [u8; 32] = [42_u8; 32];

// usually we store two types of data:
// 1. account, with size = 2xHASH+2xU256
// 2. storage = HASH
// so 150 bytes is realistic assumption.
const VALUE_SIZE_BYTES: usize = 150;

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

macro_rules! generate_bench {
    (
        @ $timing:ident
        declare($name: expr, $c:ident: &mut Criterion);
        fn init($bench_seed:ident, $setup_seed:ident,
            $bench_amount:ident, $setup_amount:ident
        ) {$($con_body: tt)*}
        let $db: ident = $construct: expr;
        let $this: ident = $process: expr;

        fn apply() => $apply: expr;
        fn reconstruct($root: ident) => $reconstruct: expr;
        fn get($get_key: ident) => $get: expr;
        fn insert($insert_key: ident, $insert_value: ident) => $insert: expr;
    ) => {
        #[allow(redundant_semicolons)]
            $c.bench_function(&format!(concat!("{}::",stringify!($timing)), $name), |b| {
                b.iter_custom(|num_iters| {
                    let prep: Vec<_> = rand_collection($setup_seed, $setup_amount).collect();

                    let test_data: Vec<_> = rand_collection($bench_seed, $bench_amount).collect();
                    $($con_body)*;
                    let $db = $construct;
                    #[allow(unused_mut)]
                    let mut $this = $process;

                    for ($insert_key, $insert_value) in prep {
                        $insert;
                    }
                    let $root = $apply;
                    let mut apply = Duration::default();
                    let mut get = Duration::default();
                    let mut insert = Duration::default();
                    let mut reconstruct_gc = Duration::default();

                    for _iter in 0..num_iters {

                        let start = Instant::now();
                        #[allow(unused_mut)]
                        let mut $this = $reconstruct;
                        reconstruct_gc += start.elapsed();

                        let test_data = test_data.clone();

                        let start = Instant::now();
                        // Start benchmark
                        for ($get_key, _) in &test_data {
                            $get;
                        }
                        get += start.elapsed();

                        let start = Instant::now();
                        // Start benchmark
                        for ($insert_key, $insert_value) in test_data {
                            $insert;
                        }
                        insert += start.elapsed();

                        let start = Instant::now();
                        let _new_root = $apply;
                        apply += start.elapsed();

                        let start = Instant::now();
                        drop(_new_root);
                        reconstruct_gc += start.elapsed();
                    }
                    // + is used because macro produce expression, when we choose one of accumulator, only choosen one is set, remaining is produce zero
                    Duration::default() +
                    generate_bench!(@timing => insert, $timing) +

                    generate_bench!(@timing => get, $timing) +

                    generate_bench!(@timing => apply, $timing) +

                    generate_bench!(@timing => reconstruct_gc, $timing)
                });
            });

    };
    // just bind $name as ident and as macro binding
    (@timing => $name:ident, $timing: ident) => ( generate_bench!(@timing => $name, $name, $timing));

    // match table that choose accumulator, based on name, and type of generated benchmark
    (@timing => insert, $insert: ident, insert) => ( $insert );
    (@timing => apply, $apply: ident, apply) => ( $apply );
    (@timing => reconstruct_gc, $reconstruct_gc: ident, reconstruct_gc) => ( $reconstruct_gc );
    (@timing => get, $get: ident, get) => ( $get );
    // by default return zero
    (@timing => $any: ident, $any2: ident, $any3: ident) => ( Duration::default() );

    // Generate benchmark by type
    ($($tokens:tt)*) =>
    {
        generate_bench!(@insert $($tokens)*);

        generate_bench!(@get $($tokens)*);

        generate_bench!(@apply $($tokens)*);

        generate_bench!(@reconstruct_gc $($tokens)*);

    };
}

/// Test different collections
/// Reconstruct = cleanup + cost of recreating the test collection - In other word const of reverting to base state.
/// apply = write changes to storage.
fn bench_backends(
    c: &mut Criterion,
    (bench_seed, setup_seed): ([u8; 32], [u8; 32]),
    (bench_amount, setup_amount): (usize, usize),
) {
    generate_bench! {
        declare("TrieCollection<Rocks>", c: &mut Criterion);
        fn init(bench_seed, setup_seed,
            bench_amount, setup_amount) {
            use triedb::empty_trie_hash;
            use triedb::rocksdb::merge_counter;
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
        }
        let collection = TrieCollection::new(handle);
        let this = collection.trie_for(empty_trie_hash());
        fn apply() => collection.apply_increase(this.into_patch(), no_childs);
        fn reconstruct(root) => collection.trie_for(root.root);
        fn get(key)  => this.get(&key.as_ref());
        fn insert(key, value) => this.insert(&key.as_ref(), &value);
    }

    generate_bench! {
        declare("TrieCollection<Memory>", c: &mut Criterion);
        fn init(bench_seed, setup_seed, bench_amount, setup_amount) {
            use triedb::empty_trie_hash;
            use triedb::gc::MapWithCounterCached;

            let handle = MapWithCounterCached::default();
        }
        let collection = TrieCollection::new(handle);
        let this = collection.trie_for(empty_trie_hash());
        fn apply() => collection.apply_increase(this.into_patch(), no_childs);
        fn reconstruct(root) => collection.trie_for(root.root);
        fn get(key)  => this.get(&key.as_ref());
        fn insert(key, value) => this.insert(&key.as_ref(), &value);
    }

    generate_bench! {
        declare("HashMap", c: &mut Criterion);
        fn init(bench_seed, setup_seed,
            bench_amount, setup_amount) {
        }
        let collection = HashMap::<Vec<u8>, Vec<u8>>::new();
        let this = collection;
        fn apply() => ();
        fn reconstruct(_root) => this.clone();
        fn get(key)  => this.get(key.as_ref());
        fn insert(key, value) => this.insert(key.as_ref().to_vec(), value.as_ref().to_vec());
    }

    generate_bench! {
        declare("DashMap", c: &mut Criterion);
        fn init(bench_seed, setup_seed,
            bench_amount, setup_amount) {
        }
        let collection = DashMap::<Vec<u8>, Vec<u8>>::new();
        let this = collection;
        fn apply() => ();
        fn reconstruct(_root) => this.clone();
        fn get(key)  => this.get(key.as_ref());
        fn insert(key, value) => this.insert(key.as_ref().to_vec(), value.as_ref().to_vec());
    }
    generate_bench! {
        declare("Rocksdb(without recreate/cleanup)", c: &mut Criterion);
        fn init(bench_seed, setup_seed,
            bench_amount, setup_amount) {
            let dir = tempdir().unwrap();
        }
        let collection = DB::open_default(&dir).unwrap();
        let this = &collection;
        fn apply() => ();
        fn reconstruct(_root) => &collection;
        fn get(key)  => this.get(&key.as_ref()).unwrap();
        fn insert(key, value) => this.put(key.as_ref(), value.as_ref()).unwrap();
    }

    generate_bench! {
        declare("MemoryTrieMut", c: &mut Criterion);
        fn init(bench_seed, setup_seed,
            bench_amount, setup_amount) {
        }
        let collection = MemoryTrieMut::default();
        let this = collection.clone();
        fn apply() => this;
        fn reconstruct(root) => root.clone();
        fn get(key)  => this.get(&key.as_ref());
        fn insert(key, value) => this.insert(key.as_bytes(), value.as_ref());
    }
}

fn no_childs(_data: &[u8]) -> Vec<H256> {
    vec![]
}

fn bench_db_backends(c: &mut Criterion) {
    bench_backends(c, (BENCH_SEED, PREP_SEED), (BENCH_AMOUNT, PREP_SIZE))
}

criterion_group!(benches, bench_db_backends);
criterion_main!(benches);
