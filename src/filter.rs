//! XOR16-based DNS domain filter with subdomain matching and runtime allowlist.
//!
//! ## Architecture
//!
//! - [`BlocklistFilter`]: Immutable, serialized XOR16 filter built from blocklist domains.
//!   Pre-built at CI/server time, shipped as `filter.bin` (~1.2MB for 500k domains).
//! - [`FilterEngine`]: Runtime query engine combining BlocklistFilter + user allowlist.
//!   Performs subdomain hierarchy walking for both block and allow checks.
//!
//! ## Subdomain matching
//!
//! A blocked domain `xmode.io` also blocks `api.xmode.io`,
//! `track.xmode.io`, etc. This is standard Pi-hole/AdGuard behavior.
//!
//! ## False positive rate
//!
//! Xor16 has <0.002% per lookup. With max ~7 subdomain
//! hierarchy checks, compound rate is ~0.014% (1 in ~7000 queries).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use xorf::{Filter as XorFilterTrait, Xor16};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FilterError {
    Build(String),
    Io(io::Error),
    Deserialize(bincode::Error),
}

impl From<io::Error> for FilterError {
    fn from(e: io::Error) -> Self {
        FilterError::Io(e)
    }
}

impl From<bincode::Error> for FilterError {
    fn from(e: bincode::Error) -> Self {
        FilterError::Deserialize(e)
    }
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterError::Build(msg) => write!(f, "filter build error: {msg}"),
            FilterError::Io(e) => write!(f, "io error: {e}"),
            FilterError::Deserialize(e) => write!(f, "deserialize error: {e}"),
        }
    }
}

impl std::error::Error for FilterError {}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Result of a domain lookup against the filter engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Domain is blocked. `matched_rule` is the blocklist entry that triggered the block
    /// (may be a parent domain due to subdomain matching).
    Blocked { matched_rule: String },
    /// Domain is allowed (not in blocklist, or explicitly allowlisted).
    Allowed,
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Blocked { .. })
    }
}

// ---------------------------------------------------------------------------
// BlocklistFilter (serializable, pre-built)
// ---------------------------------------------------------------------------

/// Version tag for forward-compatible deserialization.
const FILTER_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct SerializedFilter {
    version: u32,
    domain_count: u32,
    filter: Xor16,
}

/// Immutable XOR16-based blocklist filter.
///
/// Built from a list of domains at CI/server time. Serialized to bytes for
/// distribution as `filter.bin`. On Android, loaded directly; on iOS, can be
/// memory-mapped to avoid heap allocation.
pub struct BlocklistFilter {
    inner: SerializedFilter,
}

impl BlocklistFilter {
    /// Build a new filter from an iterator of domain strings.
    ///
    /// Domains are normalized (lowercase, trimmed, trailing dot removed)
    /// and deduplicated before building the XOR16 filter.
    pub fn build<'a>(domains: impl Iterator<Item = &'a str>) -> Result<Self, FilterError> {
        let mut hashes: Vec<u64> = domains.map(|d| hash_domain(&normalize(d))).collect();

        if hashes.is_empty() {
            return Err(FilterError::Build("empty domain list".into()));
        }

        // Deduplicate: xorf requires unique keys
        hashes.sort_unstable();
        hashes.dedup();

        let domain_count = hashes.len() as u32;
        let filter = Xor16::from(&hashes);

        Ok(BlocklistFilter {
            inner: SerializedFilter {
                version: FILTER_VERSION,
                domain_count,
                filter,
            },
        })
    }

    /// Serialize the filter to bytes (bincode format).
    pub fn to_bytes(&self) -> Result<Vec<u8>, FilterError> {
        bincode::serialize(&self.inner).map_err(FilterError::from)
    }

    /// Deserialize a filter from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FilterError> {
        let inner: SerializedFilter = bincode::deserialize(bytes)?;
        if inner.version != FILTER_VERSION {
            return Err(FilterError::Deserialize(Box::new(bincode::ErrorKind::Custom(
                format!(
                    "unsupported filter version: {} (expected {})",
                    inner.version, FILTER_VERSION
                ),
            ))));
        }
        Ok(BlocklistFilter { inner })
    }

    /// Number of unique domains in the blocklist.
    pub fn domain_count(&self) -> u32 {
        self.inner.domain_count
    }

    /// Raw XOR16 membership test (single hash, no subdomain walking).
    fn contains_hash(&self, hash: u64) -> bool {
        self.inner.filter.contains(&hash)
    }
}

// ---------------------------------------------------------------------------
// FilterEngine (runtime query engine)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Block statistics (for transparency dashboard)
// ---------------------------------------------------------------------------

/// Per-domain block counter for the transparency dashboard.
/// "Muslim Pro tried to reach X-Mode 42 times today."
pub struct BlockStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    /// Domain → block count (matched_rule → count)
    pub blocked_domains: Vec<(String, u64)>,
}

/// Runtime DNS filter combining a pre-built blocklist with a user-managed allowlist.
///
/// The allowlist takes precedence: if a domain (or any parent domain) is in
/// the allowlist, it will not be blocked regardless of the blocklist.
///
/// Tracks block statistics for the transparency dashboard.
///
/// Thread-safe: all fields use atomic or lock-based synchronization,
/// so `check()` can be called from the VPN packet loop while
/// `allow()`/`disallow()` are called from the UI thread via JNI.
pub struct FilterEngine {
    blocklist: BlocklistFilter,
    allowlist: RwLock<HashSet<u64>>,
    total_queries: AtomicU64,
    blocked_queries: AtomicU64,
    blocked_domain_counts: std::sync::Mutex<HashMap<String, u64>>,
}

impl FilterEngine {
    /// Create a new engine from a pre-built blocklist filter.
    pub fn new(blocklist: BlocklistFilter) -> Self {
        FilterEngine {
            blocklist,
            allowlist: RwLock::new(HashSet::new()),
            total_queries: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            blocked_domain_counts: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Add a domain to the allowlist. Also allows all subdomains.
    /// Thread-safe: acquires write lock.
    pub fn allow(&self, domain: &str) {
        if let Ok(mut set) = self.allowlist.write() {
            set.insert(hash_domain(&normalize(domain)));
        }
    }

    /// Remove a domain from the allowlist.
    /// Thread-safe: acquires write lock.
    pub fn disallow(&self, domain: &str) {
        if let Ok(mut set) = self.allowlist.write() {
            set.remove(&hash_domain(&normalize(domain)));
        }
    }

    /// Clear the entire allowlist.
    pub fn clear_allowlist(&self) {
        if let Ok(mut set) = self.allowlist.write() {
            set.clear();
        }
    }

    /// Number of domains in the blocklist.
    pub fn blocklist_count(&self) -> u32 {
        self.blocklist.domain_count()
    }

    /// Number of domains in the allowlist.
    pub fn allowlist_count(&self) -> usize {
        self.allowlist.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Check whether a domain should be blocked.
    ///
    /// Walks up the domain hierarchy (e.g., `api.track.xmode.io` →
    /// `track.xmode.io` → `xmode.io` → `io`) checking allowlist first,
    /// then blocklist at each level.
    ///
    /// - If any ancestor is in the allowlist → `Verdict::Allowed`
    /// - If any ancestor is in the blocklist → `Verdict::Blocked`
    /// - Otherwise → `Verdict::Allowed`
    pub fn check(&self, domain: &str) -> Verdict {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let normalized = normalize(domain);

        // Phase 1: Walk up checking allowlist (read lock, released before phase 2)
        if let Ok(allowlist) = self.allowlist.read() {
            let mut cursor = normalized.as_str();
            loop {
                let hash = hash_domain(cursor);
                if allowlist.contains(&hash) {
                    return Verdict::Allowed;
                }
                match cursor.find('.') {
                    Some(pos) => cursor = &cursor[pos + 1..],
                    None => break,
                }
            }
        }

        // Phase 2: Walk up checking blocklist
        let mut cursor = normalized.as_str();
        loop {
            let hash = hash_domain(cursor);
            if self.blocklist.contains_hash(hash) {
                self.blocked_queries.fetch_add(1, Ordering::Relaxed);
                let rule = cursor.to_string();
                if let Ok(mut counts) = self.blocked_domain_counts.lock() {
                    *counts.entry(rule.clone()).or_insert(0) += 1;
                }
                return Verdict::Blocked {
                    matched_rule: rule,
                };
            }
            match cursor.find('.') {
                Some(pos) => cursor = &cursor[pos + 1..],
                None => break,
            }
        }

        Verdict::Allowed
    }

    /// Get current block statistics for the transparency dashboard.
    /// Returns domains sorted by block count (descending).
    pub fn stats(&self) -> BlockStats {
        let total_queries = self.total_queries.load(Ordering::Relaxed);
        let blocked_queries = self.blocked_queries.load(Ordering::Relaxed);
        let blocked_domains = if let Ok(counts) = self.blocked_domain_counts.lock() {
            let mut pairs: Vec<(String, u64)> =
                counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            pairs
        } else {
            Vec::new()
        };

        BlockStats {
            total_queries,
            blocked_queries,
            blocked_domains,
        }
    }

    /// Reset all statistics counters.
    pub fn reset_stats(&self) {
        self.total_queries.store(0, Ordering::Relaxed);
        self.blocked_queries.store(0, Ordering::Relaxed);
        if let Ok(mut counts) = self.blocked_domain_counts.lock() {
            counts.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Domain hashing utilities
// ---------------------------------------------------------------------------

/// Normalize a domain for consistent hashing.
pub fn normalize(domain: &str) -> String {
    let d = domain.trim().to_ascii_lowercase();
    d.strip_suffix('.').unwrap_or(&d).to_string()
}

/// FNV-1a 64-bit hash. Non-cryptographic, fast, excellent distribution.
/// Used to convert domain strings to u64 keys for the XOR filter.
fn hash_domain(domain: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for byte in domain.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_domains() -> Vec<&'static str> {
        vec![
            "api.xmode.io",
            "api.smartechmetrics.com",
            "track.muslimpro.com",
            "adjust.com",
            "graph.facebook.com",
            "analytics.google.com",
            "ad.doubleclick.net",
            "predicio.fr",
            "xmode.io",
        ]
    }

    fn build_test_engine() -> FilterEngine {
        let domains = tracker_domains();
        let filter = BlocklistFilter::build(domains.into_iter()).unwrap();
        FilterEngine::new(filter)
    }

    // --- Basic blocking ---

    #[test]
    fn blocks_exact_match() {
        let engine = build_test_engine();
        assert!(engine.check("api.xmode.io").is_blocked());
        assert!(engine.check("adjust.com").is_blocked());
        assert!(engine.check("predicio.fr").is_blocked());
    }

    #[test]
    fn allows_legitimate_domains() {
        let engine = build_test_engine();
        assert!(!engine.check("www.quran.com").is_blocked());
        assert!(!engine.check("mawaqit.net").is_blocked());
        assert!(!engine.check("sunnah.com").is_blocked());
        assert!(!engine.check("www.google.com").is_blocked());
    }

    // --- Subdomain matching ---

    #[test]
    fn blocks_subdomains_of_blocked_domain() {
        let engine = build_test_engine();
        // xmode.io is blocked → api.xmode.io, track.xmode.io should also be blocked
        assert!(engine.check("api.xmode.io").is_blocked());
        assert!(engine.check("track.xmode.io").is_blocked());
        assert!(engine.check("deep.sub.xmode.io").is_blocked());

        // adjust.com is blocked → sdk.adjust.com should also be blocked
        assert!(engine.check("sdk.adjust.com").is_blocked());
        assert!(engine.check("app.adjust.com").is_blocked());
    }

    #[test]
    fn does_not_block_sibling_domains() {
        let engine = build_test_engine();
        // ad.doubleclick.net is blocked, but other.doubleclick.net should NOT be blocked
        // (unless doubleclick.net itself is in the list, which it's not)
        assert!(!engine.check("other.doubleclick.net").is_blocked());
    }

    #[test]
    fn verdict_reports_matched_rule() {
        let engine = build_test_engine();
        // When blocking via parent domain
        if let Verdict::Blocked { matched_rule } = engine.check("deep.sub.xmode.io") {
            assert_eq!(matched_rule, "xmode.io");
        } else {
            panic!("should be blocked");
        }

        // When blocking via exact match
        if let Verdict::Blocked { matched_rule } = engine.check("predicio.fr") {
            assert_eq!(matched_rule, "predicio.fr");
        } else {
            panic!("should be blocked");
        }
    }

    // --- Allowlist ---

    #[test]
    fn allowlist_overrides_blocklist() {
        let engine = build_test_engine();

        assert!(engine.check("api.xmode.io").is_blocked());

        engine.allow("api.xmode.io");
        assert!(!engine.check("api.xmode.io").is_blocked());
    }

    #[test]
    fn allowlist_covers_subdomains() {
        let engine = build_test_engine();

        // Block xmode.io → blocks track.xmode.io
        assert!(engine.check("track.xmode.io").is_blocked());

        // Allow xmode.io → track.xmode.io should also be allowed
        engine.allow("xmode.io");
        assert!(!engine.check("track.xmode.io").is_blocked());
        assert!(!engine.check("api.xmode.io").is_blocked());
        assert!(!engine.check("deep.sub.xmode.io").is_blocked());
    }

    #[test]
    fn disallow_removes_from_allowlist() {
        let engine = build_test_engine();

        engine.allow("api.xmode.io");
        assert!(!engine.check("api.xmode.io").is_blocked());

        engine.disallow("api.xmode.io");
        assert!(engine.check("api.xmode.io").is_blocked());
    }

    #[test]
    fn clear_allowlist_reblocks_all() {
        let engine = build_test_engine();

        engine.allow("xmode.io");
        engine.allow("adjust.com");
        assert!(!engine.check("api.xmode.io").is_blocked());
        assert!(!engine.check("sdk.adjust.com").is_blocked());

        engine.clear_allowlist();
        assert!(engine.check("api.xmode.io").is_blocked());
        assert!(engine.check("sdk.adjust.com").is_blocked());
    }

    // --- Case insensitivity and normalization ---

    #[test]
    fn case_insensitive() {
        let engine = build_test_engine();
        assert!(engine.check("API.XMODE.IO").is_blocked());
        assert!(engine.check("Api.Xmode.Io").is_blocked());
    }

    #[test]
    fn handles_trailing_dot() {
        let engine = build_test_engine();
        assert!(engine.check("api.xmode.io.").is_blocked());
    }

    #[test]
    fn handles_whitespace() {
        let engine = build_test_engine();
        assert!(engine.check("  api.xmode.io  ").is_blocked());
    }

    // --- Serialization round-trip ---

    #[test]
    fn serialize_deserialize_roundtrip() {
        let domains = tracker_domains();
        let filter = BlocklistFilter::build(domains.into_iter()).unwrap();
        let bytes = filter.to_bytes().unwrap();
        let loaded = BlocklistFilter::from_bytes(&bytes).unwrap();
        let engine = FilterEngine::new(loaded);

        assert!(engine.check("api.xmode.io").is_blocked());
        assert!(engine.check("deep.sub.xmode.io").is_blocked());
        assert!(!engine.check("www.quran.com").is_blocked());
    }

    #[test]
    fn serialized_size_compact() {
        let domains: Vec<String> = (0..10_000).map(|i| format!("tracker-{i}.example.com")).collect();
        let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        let filter = BlocklistFilter::build(refs.into_iter()).unwrap();
        let bytes = filter.to_bytes().unwrap();

        // 10k domains with Xor16 should be well under 200KB
        assert!(
            bytes.len() < 200_000,
            "filter too large: {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn empty_list_returns_error() {
        let result = BlocklistFilter::build(std::iter::empty());
        assert!(result.is_err());
    }

    #[test]
    fn deduplicates_domains() {
        let domains = vec!["xmode.io", "xmode.io", "XMODE.IO", "xmode.io."];
        let filter = BlocklistFilter::build(domains.into_iter()).unwrap();
        // All four normalize to the same domain → count should be 1
        assert_eq!(filter.domain_count(), 1);
    }

    // --- Large-scale correctness ---

    #[test]
    fn large_blocklist_no_false_negatives() {
        let domains: Vec<String> = (0..50_000).map(|i| format!("tracker-{i}.ad.com")).collect();
        let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        let filter = BlocklistFilter::build(refs.into_iter()).unwrap();
        let engine = FilterEngine::new(filter);

        // XOR filters guarantee zero false negatives
        for domain in &domains {
            assert!(
                engine.check(domain).is_blocked(),
                "false negative on {domain}"
            );
        }
    }

    #[test]
    fn large_blocklist_acceptable_false_positive_rate() {
        let domains: Vec<String> = (0..50_000).map(|i| format!("tracker-{i}.ad.com")).collect();
        let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        let filter = BlocklistFilter::build(refs.into_iter()).unwrap();
        let engine = FilterEngine::new(filter);

        // Test 10,000 definitely-not-in-list domains
        let false_positives: usize = (0..10_000)
            .map(|i| format!("legit-site-{i}.example.org"))
            .filter(|d| engine.check(d).is_blocked())
            .count();

        // Xor16 FP rate: <0.002%. With subdomain walk (1 extra check for .example.org),
        // compound rate ~0.004%. For 10k queries, expect <1 FP on average.
        // Allow up to 5 for test stability.
        assert!(
            false_positives <= 5,
            "too many false positives: {false_positives}/10000 ({:.3}%)",
            false_positives as f64 / 100.0
        );
    }
}
