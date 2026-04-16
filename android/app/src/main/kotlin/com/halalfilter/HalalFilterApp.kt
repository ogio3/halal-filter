package com.halalfilter

import android.app.Application
import android.content.Context
import android.util.Log
import com.halalfilter.bridge.NativeFilter

class HalalFilterApp : Application() {

    companion object {
        private const val TAG = "HalalFilterApp"
    }

    @Volatile
    private var engineHandle: Long = 0

    override fun onCreate() {
        super.onCreate()
        NativeFilter.init()
        Log.i(TAG, "Application created, native engine initialized")
    }

    /**
     * Get or create the filter engine singleton.
     * Loads filter.bin from app assets on first call.
     */
    @Synchronized
    fun getOrCreateEngine(): Long {
        if (engineHandle != 0L) return engineHandle

        return try {
            val bytes = assets.open("filter.bin").use { it.readBytes() }
            val handle = NativeFilter.createEngine(bytes)
            if (handle == 0L) {
                Log.e(TAG, "NativeFilter.createEngine returned null handle")
                0L
            } else {
                engineHandle = handle
                val count = NativeFilter.getBlocklistCount(handle)
                Log.i(TAG, "Filter engine loaded: $count domains")

                // Restore persisted allowlist
                val prefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
                val allowed = prefs.getStringSet("allowed_domains", emptySet()) ?: emptySet()
                for (domain in allowed) {
                    NativeFilter.addAllowlist(handle, domain)
                }
                if (allowed.isNotEmpty()) {
                    Log.i(TAG, "Restored ${allowed.size} allowlisted domains")
                }

                handle
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load filter.bin", e)
            0L
        }
    }

    fun getEngineHandle(): Long = engineHandle

    /**
     * Safely destroy the filter engine. Clears the handle FIRST to prevent
     * other threads from using a stale pointer, then frees the Rust memory.
     *
     * Not currently called (engine is process-scoped, OS reclaims on death),
     * but provided for future use (e.g., filter.bin hot-reload).
     */
    @Synchronized
    fun destroyEngine() {
        val h = engineHandle
        if (h != 0L) {
            engineHandle = 0
            NativeFilter.destroyEngine(h)
            Log.i(TAG, "Filter engine destroyed")
        }
    }
}
