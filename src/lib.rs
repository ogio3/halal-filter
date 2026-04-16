//! halal-filter — Privacy-focused DNS filtering engine.
//!
//! Core library for intercepting and filtering DNS queries targeting
//! surveillance SDKs (X-Mode, Predicio, etc.) embedded in Muslim lifestyle apps.
//!
//! Designed as a cross-platform Rust core:
//! - Android: linked via JNI/uniffi-rs, driven by VpnService
//! - iOS: linked via C-FFI, driven by NEPacketTunnelProvider
//!
//! # Architecture
//!
//! ```text
//! Raw IP/UDP packet (from VpnService FileDescriptor)
//!     → DnsPacket::parse()      — extract QNAME
//!     → FilterEngine::check()   — XOR16 blocklist + allowlist
//!     → DnsResponse::blocked()  — forge 0.0.0.0 response
//!     → write back to FileDescriptor
//! ```

mod dns;
mod filter;
#[cfg(target_os = "android")]
mod jni_bridge;
mod parser;

pub use dns::{DnsError, DnsPacket, DnsResponse};
pub use filter::{BlockStats, BlocklistFilter, FilterEngine, FilterError, Verdict};
pub use parser::{merge_results, parse_blocklist, ParseError, ParseResult};
