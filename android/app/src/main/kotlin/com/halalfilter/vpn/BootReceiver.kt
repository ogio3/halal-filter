package com.halalfilter.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import com.halalfilter.MainActivity

/**
 * Restarts VPN service on device boot if it was previously enabled.
 *
 * Checks VPN consent before starting — if consent has expired (some OEMs
 * revoke it on reboot), shows a notification asking the user to re-authorize
 * instead of starting a service that will silently fail.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val prefs = context.getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
        val wasEnabled = prefs.getBoolean("vpn_enabled", false)

        if (!wasEnabled) return

        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent == null) {
            // VPN consent still valid — safe to restart
            Log.i("BootReceiver", "Restarting VPN after boot (consent valid)")
            val vpnIntent = Intent(context, HalalVpnService::class.java)
            context.startForegroundService(vpnIntent)
        } else {
            // Consent expired — show notification to re-authorize
            Log.w("BootReceiver", "VPN consent expired after reboot, showing re-auth notification")
            showReauthorizeNotification(context)
        }
    }

    private fun showReauthorizeNotification(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)

        // Ensure alert channel exists (may not have been created if service hasn't run yet)
        val channel = NotificationChannel(
            HalalVpnService.CHANNEL_ALERT_ID,
            "Protection Alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Alerts when DNS protection is unexpectedly disabled"
        }
        manager.createNotificationChannel(channel)

        val reopenIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingReopen = PendingIntent.getActivity(
            context, 3, reopenIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = Notification.Builder(context, HalalVpnService.CHANNEL_ALERT_ID)
            .setContentTitle("Protection Stopped")
            .setContentText("Halal Filter needs permission to restart after reboot. Tap to re-enable.")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentIntent(pendingReopen)
            .setAutoCancel(true)
            .build()

        manager.notify(HalalVpnService.ALERT_NOTIFICATION_ID, notification)
    }
}
