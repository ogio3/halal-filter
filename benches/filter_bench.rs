use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halal_filter::{BlocklistFilter, FilterEngine};

fn generate_blocklist(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("tracker-{i}.ad-network.com"))
        .collect()
}

fn bench_lookup(c: &mut Criterion) {
    let domains = generate_blocklist(500_000);
    let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let filter = BlocklistFilter::build(refs.into_iter()).unwrap();
    let engine = FilterEngine::new(filter);

    c.bench_function("xor16_check_blocked_exact", |b| {
        b.iter(|| engine.check(black_box("tracker-42.ad-network.com")))
    });

    c.bench_function("xor16_check_blocked_subdomain", |b| {
        b.iter(|| engine.check(black_box("deep.sub.tracker-42.ad-network.com")))
    });

    c.bench_function("xor16_check_allowed", |b| {
        b.iter(|| engine.check(black_box("www.quran.com")))
    });
}

fn bench_build(c: &mut Criterion) {
    let domains = generate_blocklist(500_000);
    let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

    c.bench_function("xor16_build_500k", |b| {
        b.iter(|| BlocklistFilter::build(black_box(refs.clone().into_iter())))
    });
}

fn bench_serialization(c: &mut Criterion) {
    let domains = generate_blocklist(500_000);
    let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    let filter = BlocklistFilter::build(refs.into_iter()).unwrap();
    let bytes = filter.to_bytes().unwrap();

    c.bench_function("xor16_load_500k", |b| {
        b.iter(|| BlocklistFilter::from_bytes(black_box(&bytes)))
    });

    println!(
        "\n  Filter size for 500k domains: {} bytes ({:.2} MB)",
        bytes.len(),
        bytes.len() as f64 / 1_048_576.0
    );
}

criterion_group!(benches, bench_lookup, bench_build, bench_serialization);
criterion_main!(benches);
