use criterion::{criterion_group, criterion_main, Criterion};

use triedb::merkle::nibble::{from_key, into_key, Nibble};

fn bench_from_into_key(c: &mut Criterion) {
    let key = [1, 2, 3, 4, 5, 6, 7, 8, 4, 3, 2, 1, 8, 7, 6, 5];

    c.bench_function("from_key bench", |b| b.iter(|| from_key(&key)));

    let nibble = [
        Nibble::N0,
        Nibble::N1,
        Nibble::N2,
        Nibble::N3,
        Nibble::N4,
        Nibble::N5,
        Nibble::N6,
        Nibble::N7,
        Nibble::N8,
        Nibble::N9,
        Nibble::N10,
        Nibble::N11,
        Nibble::N12,
        Nibble::N13,
        Nibble::N14,
    ];

    c.bench_function("into_key bench", |b| b.iter(|| into_key(&nibble)));
}

criterion_group!(benches, bench_from_into_key);
criterion_main!(benches);
