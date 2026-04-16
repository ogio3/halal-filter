package com.halalfilter

import android.app.Application
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
                handle
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load filter.bin", e)
            0L
        }
    }

    fun getEngineHandle(): Long = engineHandle

    override fun onTerminate() {
        if (engineHandle != 0L) {
            NativeFilter.destroyEngine(engineHandle)
            engineHandle = 0
        }
        super.onTerminate()
    }
}
