use rand::{rngs::StdRng, thread_rng, SeedableRng};
use std::fmt;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use hex_literal::hex;
use primitive_types::H256;
use rand::seq::index::sample;

use triedb::{
    empty_trie_hash,
    gc::{testing::MapWithCounterCached, TrieCollection},
    state_diff::DiffFinder,
    TrieMut,
};

pub fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}

struct Params {
    l_trie_size: usize,
    l_trie_range: (usize, usize),
    r_trie_size: usize,
    r_trie_range: (usize, usize),
}

impl Params {
    fn new(
        l_trie_size: usize,
        l_trie_range: (usize, usize),
        r_trie_size: usize,
        r_trie_range: (usize, usize),
    ) -> Self {
        assert!(l_trie_range.0 < l_trie_range.1);
        assert!(r_trie_range.0 < r_trie_range.1);
        Params {
            l_trie_size,
            l_trie_range,
            r_trie_size,
            r_trie_range,
        }
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(l_size={}, l_range={:?}, r_size={}, r_range={:?})",
            self.l_trie_size, self.l_trie_range, self.r_trie_size, self.r_trie_range
        )
    }
}

fn benchmark_diff(c: &mut Criterion) {
    /// Errors:
    /// - Params::new(10, (0, 10000), 100, (0, 10000)) - Diff work only with fixed sized key
    /// - Params::new(100, (0, 10000), 100, (0, 10000)) - Found different nodes, with same prefix and data
    let mut group = c.benchmark_group("get_changeset");
    let mut rng = StdRng::seed_from_u64(0);
    vec![
        (1000, (0, 10_000), 1000, (0, 10_000)),
        (1000, (0, 10_000), 1000, (usize::MAX - 10_000, usize::MAX)),
        (10000, (0, 100_000), 10000, (0, 100000)),
        (10000, (0, 100_000), 10000, (usize::MAX - 100_000, usize::MAX)),
    ]
    .into_iter()
    .map(|(lsize, lrange, rsize, rrange)| Params::new(lsize, lrange, rsize, rrange))
    .for_each(|params| {
        let keys1: Vec<_> = sample(
            &mut rng,
            params.l_trie_range.1 - params.l_trie_range.0,
            params.l_trie_size,
        )
        .iter()
        .map(|n| n + params.l_trie_range.0)
        .map(|n| n.to_be_bytes())
        .collect();
        let keys2: Vec<_> = sample(
            &mut rng,
            params.r_trie_range.1 - params.r_trie_range.0,
            params.r_trie_size,
        )
        .iter()
        .map(|n| n + params.r_trie_range.0)
        .map(|n| n.to_be_bytes())
        .collect();

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie = collection.trie_for(empty_trie_hash());
        for key in &keys1 {
            trie.insert(key, key);
        }
        let patch = trie.into_patch();
        let first_root = collection.apply_increase(patch, no_childs);

        let mut trie = collection.trie_for(empty_trie_hash());
        for key in &keys2 {
            trie.insert(key, key);
        }
        let patch = trie.into_patch();
        let second_root = collection.apply_increase(patch, no_childs);

        group.bench_with_input(
            BenchmarkId::from_parameter(&params),
            &params,
            |b, _params| {
                b.iter(|| {
                    let st =
                        DiffFinder::new(&collection.database, first_root.root, second_root.root);
                    st.get_changeset(first_root.root, second_root.root).unwrap()
                })
            },
        );
    });
}

fn benchmark_diff_equal_tries(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let collection = TrieCollection::new(MapWithCounterCached::default());
    let mut trie = collection.trie_for(empty_trie_hash());
    sample(&mut rng, 100000, 10000)
        .iter()
        .map(|n| n.to_be_bytes())
        .for_each(|key| trie.insert(&key, &key));
    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, no_childs);

    c.bench_function("get_changeset equal", |b| {
        b.iter(|| {
            let st = DiffFinder::new(&collection.database, first_root.root, first_root.root);
            st.get_changeset(first_root.root, first_root.root).unwrap()
        })
    });
}

criterion_group!(benches, benchmark_diff, benchmark_diff_equal_tries);
criterion_main!(benches);
