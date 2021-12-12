use criterion::{criterion_group, criterion_main, Criterion};

use triedb::merkle::nibble::{from_key, into_key, Nibble};

fn bench_from_into_key(c: &mut Criterion) {
    let key = [
        218, 213, 224, 55, 235, 202, 194, 55, 196, 75, 128, 94, 41, 203, 212, 119, 52, 78, 253,
        230, 158, 82, 213, 179, 165, 165, 195, 26, 223, 64, 188, 206,
    ];

    c.bench_function("bench from_key", |b| b.iter(|| from_key(&key)));

    let nibbles = [
        1u8, 8, 1, 14, 6, 5, 1, 1, 6, 11, 14, 1, 7, 8, 3, 0, 4, 6, 13, 10, 11, 7, 1, 7, 9, 9, 7,
        15, 4, 11, 5, 5, 11, 2, 7, 4, 13, 13, 15, 1, 13, 8, 1, 14, 8, 5, 8, 14, 8, 1, 7, 4, 9, 14,
        3, 7, 1, 10, 7, 4, 9, 9, 1, 10,
    ]
    .map(Nibble::from);

    c.bench_function("bench into_key", |b| b.iter(|| into_key(&nibbles)));
}

criterion_group!(benches, bench_from_into_key);
criterion_main!(benches);
