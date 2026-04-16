package com.halalfilter.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Restarts VPN service on device boot if it was previously enabled.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val prefs = context.getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
        val wasEnabled = prefs.getBoolean("vpn_enabled", false)

        if (wasEnabled) {
            Log.i("BootReceiver", "Restarting VPN after boot")
            val vpnIntent = Intent(context, HalalVpnService::class.java)
            context.startForegroundService(vpnIntent)
        }
    }
}
