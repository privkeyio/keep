use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use keep_core::crypto::{
    blake2b_256, decrypt, derive_key, derive_subkey, encrypt, random_bytes, Argon2Params,
    SecretKey, SALT_SIZE,
};
use keep_core::frost::{sign_with_local_shares, ThresholdConfig, TrustedDealer};
use keep_core::storage::Storage;
use tempfile::tempdir;

fn bench_argon2id(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id");

    let password = b"benchmark-password-32bytes!!!!!";
    let salt: [u8; SALT_SIZE] = random_bytes();

    group.bench_function("testing", |b| {
        b.iter(|| derive_key(black_box(password), black_box(&salt), Argon2Params::TESTING))
    });

    group.bench_function("default", |b| {
        b.iter(|| derive_key(black_box(password), black_box(&salt), Argon2Params::DEFAULT))
    });

    group.bench_function("high", |b| {
        b.iter(|| derive_key(black_box(password), black_box(&salt), Argon2Params::HIGH))
    });

    group.finish();
}

fn bench_xchacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20_poly1305");

    let key = SecretKey::generate().unwrap();

    for size in [64, 256, 1024, 4096, 16384, 65536] {
        let plaintext: Vec<u8> = (0..size).map(|i| i as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &plaintext, |b, data| {
            b.iter(|| encrypt(black_box(data), black_box(&key)))
        });

        let encrypted = encrypt(&plaintext, &key).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, data| {
            b.iter(|| decrypt(black_box(data), black_box(&key)))
        });
    }

    group.finish();
}

fn bench_blake2b(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake2b");

    for size in [32, 64, 256, 1024, 4096, 16384] {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| blake2b_256(black_box(data)))
        });
    }

    group.finish();
}

fn bench_subkey_derivation(c: &mut Criterion) {
    let master = SecretKey::generate().unwrap();

    c.bench_function("subkey_derivation", |b| {
        b.iter(|| derive_subkey(black_box(&master), black_box(b"context")))
    });
}

fn bench_frost_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("frost_signing");
    group.sample_size(20);

    let message = b"benchmark message for FROST signing";

    let dealer_2of3 = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (shares_2of3, _) = dealer_2of3.generate("bench-2of3").unwrap();
    group.bench_function("2_of_3", |b| {
        b.iter(|| sign_with_local_shares(black_box(&shares_2of3[..2]), black_box(message)))
    });

    let dealer_3of5 = TrustedDealer::new(ThresholdConfig::three_of_five());
    let (shares_3of5, _) = dealer_3of5.generate("bench-3of5").unwrap();
    group.bench_function("3_of_5", |b| {
        b.iter(|| sign_with_local_shares(black_box(&shares_3of5[..3]), black_box(message)))
    });

    group.finish();
}

fn bench_frost_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("frost_keygen");
    group.sample_size(20);

    let dealer_2of3 = TrustedDealer::new(ThresholdConfig::two_of_three());
    group.bench_function("2_of_3", |b| {
        b.iter(|| dealer_2of3.generate(black_box("bench")))
    });

    let dealer_3of5 = TrustedDealer::new(ThresholdConfig::three_of_five());
    group.bench_function("3_of_5", |b| {
        b.iter(|| dealer_3of5.generate(black_box("bench")))
    });

    group.finish();
}

fn bench_vault_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault");
    group.sample_size(20);

    let password = "benchmark-password";

    let dir = tempdir().unwrap();
    let path = dir.path().join("bench-vault");
    Storage::create(&path, password, Argon2Params::TESTING).unwrap();

    group.bench_function("open", |b| b.iter(|| Storage::open(black_box(&path))));

    group.bench_function("unlock_testing", |b| {
        b.iter(|| {
            let mut storage = Storage::open(&path).unwrap();
            storage.unlock(black_box(password))
        })
    });

    let dir_default = tempdir().unwrap();
    let path_default = dir_default.path().join("bench-vault-default");
    Storage::create(&path_default, password, Argon2Params::DEFAULT).unwrap();

    group.bench_function("unlock_default", |b| {
        b.iter(|| {
            let mut storage = Storage::open(&path_default).unwrap();
            storage.unlock(black_box(password))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_argon2id,
    bench_xchacha20_poly1305,
    bench_blake2b,
    bench_subkey_derivation,
    bench_frost_signing,
    bench_frost_keygen,
    bench_vault_cycle,
);

criterion_main!(benches);
