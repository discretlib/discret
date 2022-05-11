use criterion::{black_box, criterion_group, criterion_main, Criterion};
use discret::cryptography::*;

pub fn derive_password(c: &mut Criterion) {
    c.bench_function("Derive password", |b| {
        b.iter(|| derive_pass_phrase(black_box("20".to_string()), black_box("20".to_string())))
    });
}

pub fn sign_hash(c: &mut Criterion) {
    c.bench_function("Sign hash", |b| {
        let pair = create_random_key_pair();
        let hash = hash(b"bytes");
        b.iter(|| sign(black_box(&pair), black_box(&hash)))
    });
}

pub fn verify_sign(c: &mut Criterion) {
    c.bench_function("Verify signature", |b| {
        let pair = create_random_key_pair();
        let hash = hash(b"bytes");
        let sign = sign(&pair, &hash);
        b.iter(|| verify(black_box(&pair.public), black_box(&hash), &sign))
    });
}

criterion_group!(benches, derive_password, verify_sign, sign_hash);
criterion_main!(benches);
