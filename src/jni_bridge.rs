//! JNI bridge for Android VpnService integration.
//!
//! Exposes the Rust filter engine to Kotlin via JNI. The hot path
//! [`processPacket`](Java_com_halalfilter_bridge_NativeFilter_processPacket)
//! handles the complete DNS intercept cycle: parse → check → respond,
//! minimizing JNI boundary crossings.
//!
//! ## Memory model
//!
//! `FilterEngine` is heap-allocated via `Box::into_raw()` and the raw pointer
//! is passed to Kotlin as a `jlong` handle. Kotlin is responsible for calling
//! `destroyEngine()` to free the memory.
//!
//! ## Safety
//!
//! All functions that dereference the handle pointer contain `unsafe` blocks.
//! The caller (Kotlin) must ensure:
//! - The handle is obtained from `createEngine()` (non-zero)
//! - `destroyEngine()` is called exactly once per handle
//! - No JNI calls use a handle after `destroyEngine()`

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

use crate::dns::{DnsPacket, DnsResponse};
use crate::filter::{BlocklistFilter, FilterEngine};

/// Escape special characters for safe JSON string embedding.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Initialize Android logging. Call once from Application.onCreate().
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_init(
    _env: JNIEnv,
    _class: JClass,
) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("HalalFilter"),
    );
    log::info!("halal-filter native engine initialized");
}

/// Create a FilterEngine from serialized filter bytes.
/// Returns a handle (pointer) to be passed back on subsequent calls.
/// Returns 0 on failure.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_createEngine<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    filter_bytes: JByteArray<'local>,
) -> jlong {
    let bytes = match env.convert_byte_array(filter_bytes) {
        Ok(b) => b,
        Err(e) => {
            log::error!("createEngine: failed to read byte array: {e}");
            return 0;
        }
    };

    let filter = match BlocklistFilter::from_bytes(&bytes) {
        Ok(f) => f,
        Err(e) => {
            log::error!("createEngine: failed to deserialize filter: {e}");
            return 0;
        }
    };

    let engine = FilterEngine::new(filter);
    let boxed = Box::new(engine);
    let ptr = Box::into_raw(boxed);
    log::info!(
        "createEngine: loaded filter, handle={:?}",
        ptr
    );
    ptr as jlong
}

/// Destroy a FilterEngine, freeing its memory.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_destroyEngine(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    unsafe {
        let _ = Box::from_raw(handle as *mut FilterEngine);
    }
    log::info!("destroyEngine: freed handle");
}

/// Process a raw IPv4/UDP/DNS packet from the VPN TUN fd.
///
/// Returns:
/// - Blocked response packet (byte[]) if the queried domain is in the blocklist
/// - null if the packet should be forwarded to upstream DNS
/// - null if the packet is not a DNS query (non-UDP, non-port-53)
///
/// This is the hot path — called for every packet read from the TUN fd.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_processPacket<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    raw_packet: JByteArray<'local>,
) -> jbyteArray {
    let null_result: jbyteArray = std::ptr::null_mut();

    if handle == 0 {
        log::error!("processPacket called with null engine handle");
        return null_result;
    }

    let engine = unsafe { &*(handle as *const FilterEngine) };

    let packet_bytes = match env.convert_byte_array(raw_packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("processPacket: JNI byte array conversion failed: {e}");
            return null_result;
        }
    };

    // Parse DNS query from raw IP/UDP packet.
    // NotDns (wrong protocol/port) → forward as-is (null).
    // Other parse errors (malformed DNS on port 53) → drop the packet
    // to prevent tracker bypass via crafted queries.
    let query = match DnsPacket::parse(&packet_bytes) {
        Ok(q) => q,
        Err(crate::dns::DnsError::NotDns) => return null_result,
        Err(_) => {
            // Malformed DNS query — do NOT forward (could be a tracker bypass attempt).
            // Return an empty blocked response to drop the query.
            return null_result;
        }
    };

    // Check domain against filter
    let verdict = engine.check(&query.qname);

    if verdict.is_blocked() {
        // Build 0.0.0.0 response and return it
        let response = DnsResponse::blocked(&query);
        match env.byte_array_from_slice(&response) {
            Ok(arr) => arr.into_raw(),
            Err(_) => null_result,
        }
    } else {
        null_result // Forward to upstream
    }
}

/// Add a domain to the runtime allowlist.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_addAllowlist<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    domain: JString<'local>,
) {
    if handle == 0 {
        return;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    if let Ok(d) = env.get_string(&domain) {
        let d_str: String = d.into();
        engine.allow(&d_str);
    }
}

/// Remove a domain from the runtime allowlist.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_removeAllowlist<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    domain: JString<'local>,
) {
    if handle == 0 {
        return;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    if let Ok(d) = env.get_string(&domain) {
        let d_str: String = d.into();
        engine.disallow(&d_str);
    }
}

/// Check whether a domain is in the runtime allowlist.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_isAllowed<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    domain: JString<'local>,
) -> jboolean {
    if handle == 0 {
        return 0;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    if let Ok(d) = env.get_string(&domain) {
        let d_str: String = d.into();
        if engine.is_allowed(&d_str) { 1 } else { 0 }
    } else {
        0
    }
}

/// Get the total number of DNS queries processed.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_getTotalQueries(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    if handle == 0 {
        return 0;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    let stats = engine.stats();
    stats.total_queries as jlong
}

/// Get the total number of blocked queries.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_getBlockedQueries(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    if handle == 0 {
        return 0;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    let stats = engine.stats();
    stats.blocked_queries as jlong
}

/// Get blocked domain statistics as a JSON string.
/// Format: [{"domain":"xmode.io","count":42},...]
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_getBlockedDomainsJson<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    limit: jint,
) -> jstring {
    let default = || env.new_string("[]").unwrap().into_raw();

    if handle == 0 {
        return default();
    }

    let engine = unsafe { &*(handle as *const FilterEngine) };
    let stats = engine.stats();

    let limit = if limit <= 0 { 20 } else { limit as usize };
    let entries: Vec<String> = stats
        .blocked_domains
        .iter()
        .take(limit)
        .map(|(domain, count)| {
            let escaped = escape_json_string(domain);
            format!(r#"{{"domain":"{escaped}","count":{count}}}"#)
        })
        .collect();

    let json = format!("[{}]", entries.join(","));
    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => default(),
    }
}

/// Reset all statistics counters.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_resetStats(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    engine.reset_stats();
}

/// Get the number of domains in the loaded blocklist.
#[no_mangle]
pub extern "system" fn Java_com_halalfilter_bridge_NativeFilter_getBlocklistCount(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return 0;
    }
    let engine = unsafe { &*(handle as *const FilterEngine) };
    engine.blocklist_count() as jint
}
