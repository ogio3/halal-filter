package com.halalfilter.bridge

/**
 * JNI bridge to the Rust halal-filter core engine.
 *
 * All methods are static and operate on an opaque engine handle (Long pointer).
 * The handle must be created with [createEngine] and freed with [destroyEngine].
 */
object NativeFilter {

    var isLoaded = false
        private set

    init {
        try {
            System.loadLibrary("halal_filter")
            isLoaded = true
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.e("NativeFilter", "Failed to load native library", e)
        }
    }

    /** Initialize native logging. Call once at app startup. */
    @JvmStatic
    external fun init()

    /**
     * Create a FilterEngine from serialized filter.bin bytes.
     * Returns a handle (non-zero on success, 0 on failure).
     */
    @JvmStatic
    external fun createEngine(filterBytes: ByteArray): Long

    /** Free a FilterEngine. Must be called when done. */
    @JvmStatic
    external fun destroyEngine(handle: Long)

    /**
     * Process a raw IPv4/UDP/DNS packet.
     *
     * Returns:
     * - byte[] with a blocked DNS response (0.0.0.0) if domain is in blocklist
     * - null if the packet should be forwarded to upstream DNS
     * - null if the packet is not a DNS query
     *
     * This is the hot path — called for every packet from TUN fd.
     */
    @JvmStatic
    external fun processPacket(handle: Long, rawPacket: ByteArray): ByteArray?

    /** Add a domain to the runtime allowlist. */
    @JvmStatic
    external fun addAllowlist(handle: Long, domain: String)

    /** Remove a domain from the runtime allowlist. */
    @JvmStatic
    external fun removeAllowlist(handle: Long, domain: String)

    /** Check whether a domain is in the runtime allowlist. */
    @JvmStatic
    external fun isAllowed(handle: Long, domain: String): Boolean

    /** Total DNS queries processed since last reset. */
    @JvmStatic
    external fun getTotalQueries(handle: Long): Long

    /** Total blocked queries since last reset. */
    @JvmStatic
    external fun getBlockedQueries(handle: Long): Long

    /**
     * Get blocked domain stats as JSON.
     * Format: [{"domain":"xmode.io","count":42},...]
     */
    @JvmStatic
    external fun getBlockedDomainsJson(handle: Long, limit: Int): String

    /** Reset all statistics counters. */
    @JvmStatic
    external fun resetStats(handle: Long)

    /** Number of domains in the loaded blocklist. */
    @JvmStatic
    external fun getBlocklistCount(handle: Long): Int
}
