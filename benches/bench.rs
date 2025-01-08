use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use laqf2::Laqf2;


fn benchmark(c: &mut Criterion) {
    let laqf = Laqf2::new();
    let (pk, sk) = laqf.generate_kyber_keypair();
    let data = b"Hello, world!";
    let password = "password";
    let salt = laqf.generate_salt();
    let encrypted_data = laqf.encrypt(&data[..], password, &pk, &salt);

    c.bench_with_input(BenchmarkId::new("benchmark", "v0.1.1"), &(), |b, _| {
        b.iter(|| {
            laqf.decrypt(
                black_box(&encrypted_data),
                black_box(password),
                black_box(&sk),
                black_box(&salt),
            )
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(25)
        .measurement_time(std::time::Duration::new(10, 0));
    targets = benchmark
}
criterion_main!(benches);