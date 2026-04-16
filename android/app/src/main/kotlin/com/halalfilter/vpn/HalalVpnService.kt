package com.halalfilter.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.halalfilter.HalalFilterApp
import com.halalfilter.MainActivity
import com.halalfilter.bridge.NativeFilter
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Local VPN service that intercepts DNS traffic and filters tracker domains.
 *
 * Architecture:
 * 1. Creates a TUN interface routing DNS traffic through the VPN
 * 2. Reads raw IPv4/UDP packets from the TUN file descriptor
 * 3. Passes packets to Rust core via JNI for domain checking
 * 4. Blocked domains: writes 0.0.0.0 response back to TUN
 * 5. Allowed domains: forwards to upstream DNS resolver (protected UDP)
 */
class HalalVpnService : VpnService() {

    companion object {
        private const val TAG = "HalalVpnService"
        const val CHANNEL_ID = "halal_filter_vpn"
        const val CHANNEL_ALERT_ID = "halal_filter_alert"
        private const val NOTIFICATION_ID = 1
        const val ALERT_NOTIFICATION_ID = 2
        private const val VPN_MTU = 1500

        private const val VIRTUAL_DNS = "10.0.0.2"
        private const val VIRTUAL_GATEWAY = "10.0.0.1"

        // Public DNS servers to intercept. Prevents tracker SDKs from bypassing
        // the filter by hardcoding well-known DNS resolver IPs.
        private val INTERCEPTED_DNS_SERVERS = arrayOf(
            // Google
            "8.8.8.8", "8.8.4.4",
            // Cloudflare
            "1.1.1.1", "1.0.0.1",
            // Quad9
            "9.9.9.9", "149.112.112.112",
            // OpenDNS
            "208.67.222.222", "208.67.220.220",
            // CleanBrowsing
            "185.228.168.9", "185.228.169.9",
            // AdGuard DNS
            "94.140.14.14", "94.140.15.15",
            // Comodo Secure
            "8.26.56.26", "8.20.247.20",
            // Level3 / CenturyLink
            "209.244.0.3", "209.244.0.4",
            // Verisign
            "64.6.64.6", "64.6.65.6",
            // Yandex
            "77.88.8.8", "77.88.8.1",
            // DNS.WATCH
            "84.200.69.80", "84.200.70.40",
        )

        /** True while the VPN tunnel is established and the packet loop is running. */
        @Volatile
        @JvmStatic
        var isRunning: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var engineHandle: Long = 0
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var dohResolver: DoHResolver
    private var notificationManager: NotificationManager? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        notificationManager = getSystemService(NotificationManager::class.java)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            // Verify caller is our own process to prevent external injection
            if (android.os.Binder.getCallingUid() == android.os.Process.myUid()) {
                stopVpn(userInitiated = true)
            } else {
                Log.w(TAG, "Rejecting STOP from external caller uid=${android.os.Binder.getCallingUid()}")
            }
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification(0, 0))

        if (vpnInterface == null) {
            startVpn()
        }

        return START_STICKY
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by system or another VPN app")
        stopVpn(userInitiated = false)

        // Notify user that protection was lost
        showProtectionLostAlert()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn(userInitiated = true)
        super.onDestroy()
    }

    private fun startVpn() {
        try {
            // Recreate scope in case it was cancelled by a previous stopVpn
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            dohResolver = DoHResolver(this)

            val app = application as HalalFilterApp
            engineHandle = app.getOrCreateEngine()
            if (engineHandle == 0L) {
                Log.e(TAG, "Failed to create filter engine")
                stopSelf()
                return
            }

            // Route all well-known public DNS servers through the VPN to prevent
            // tracker SDKs from bypassing the filter via hardcoded DNS IPs.
            // Full 0.0.0.0/0 routing requires userspace TCP/UDP forwarding (v0.2).
            // Carrier DNS bypass remains a gap — see Issue #16.
            val builder = Builder()
                .setSession("Halal Filter")
                .setMtu(VPN_MTU)
                .addAddress(VIRTUAL_GATEWAY, 32)
                .addDnsServer(VIRTUAL_DNS)
                .addRoute(VIRTUAL_DNS, 32)

            for (dns in INTERCEPTED_DNS_SERVERS) {
                builder.addRoute(dns, 32)
            }

            builder.setBlocking(false)

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            // Save enabled state
            getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
                .edit().putBoolean("vpn_enabled", true).apply()

            // Dismiss any "protection lost" alert
            notificationManager?.cancel(ALERT_NOTIFICATION_ID)

            isRunning = true
            Log.i(TAG, "VPN interface established, starting packet loop")
            scope.launch { packetLoop() }
            scope.launch { statsNotificationUpdater() }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            stopSelf()
        }
    }

    private fun stopVpn(userInitiated: Boolean) {
        isRunning = false
        scope.cancel()
        if (::dohResolver.isInitialized) {
            dohResolver.close()
        }
        vpnInterface?.close()
        vpnInterface = null

        if (userInitiated) {
            getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
                .edit().putBoolean("vpn_enabled", false).apply()
        }

        Log.i(TAG, "VPN stopped (userInitiated=$userInitiated)")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private suspend fun packetLoop() {
        val fd = vpnInterface ?: return
        val inputStream = FileInputStream(fd.fileDescriptor)
        val outputStream = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(VPN_MTU)
        var consecutiveErrors = 0

        while (scope.isActive) {
            try {
                val length = inputStream.read(buffer)
                if (length <= 0) {
                    delay(1)
                    continue
                }

                val packet = buffer.copyOf(length)
                val blockedResponse = NativeFilter.processPacket(engineHandle, packet)

                if (blockedResponse != null) {
                    outputStream.write(blockedResponse)
                    outputStream.flush()
                } else {
                    forwardToUpstream(packet, length, outputStream)
                }

                consecutiveErrors = 0

            } catch (e: java.io.IOException) {
                // FD closed (stopVpn race or system revoke) — exit cleanly
                if (!scope.isActive) break
                Log.e(TAG, "Packet loop IO error, stopping", e)
                withContext(Dispatchers.Main) {
                    showProtectionLostAlert()
                    stopVpn(userInitiated = false)
                }
                return
            } catch (e: Exception) {
                if (!scope.isActive) break
                consecutiveErrors++
                Log.e(TAG, "Packet loop error ($consecutiveErrors consecutive)", e)
                if (consecutiveErrors >= 5) {
                    Log.e(TAG, "Packet loop crashed $consecutiveErrors times, stopping VPN")
                    withContext(Dispatchers.Main) {
                        showProtectionLostAlert()
                        stopVpn(userInitiated = false)
                    }
                    return
                }
                delay(100)
            }
        }
    }

    /**
     * Periodically update the persistent notification with live stats.
     */
    private suspend fun statsNotificationUpdater() {
        var lastTotal = -1L
        var lastBlocked = -1L

        while (scope.isActive) {
            delay(30_000)
            if (engineHandle != 0L) {
                val total = NativeFilter.getTotalQueries(engineHandle)
                val blocked = NativeFilter.getBlockedQueries(engineHandle)

                if (total != lastTotal || blocked != lastBlocked) {
                    lastTotal = total
                    lastBlocked = blocked
                    notificationManager?.notify(
                        NOTIFICATION_ID,
                        buildNotification(total, blocked)
                    )
                }
            }
        }
    }

    private fun forwardToUpstream(
        originalPacket: ByteArray,
        length: Int,
        tunOutput: FileOutputStream
    ) {
        try {
            if (length < 28) return

            val version = (originalPacket[0].toInt() shr 4) and 0xF
            if (version != 4) return
            val protocol = originalPacket[9].toInt() and 0xFF
            if (protocol != 17) return

            val ihl = (originalPacket[0].toInt() and 0xF) * 4

            val srcIp = originalPacket.copyOfRange(12, 16)
            val dstIp = originalPacket.copyOfRange(16, 20)
            val srcPort = ((originalPacket[ihl].toInt() and 0xFF) shl 8) or
                    (originalPacket[ihl + 1].toInt() and 0xFF)
            val dstPort = ((originalPacket[ihl + 2].toInt() and 0xFF) shl 8) or
                    (originalPacket[ihl + 3].toInt() and 0xFF)

            if (dstPort != 53) return

            val dnsPayload = originalPacket.copyOfRange(ihl + 8, length)
            val responseDns = dohResolver.resolve(dnsPayload) ?: return

            val responsePacket = wrapDnsResponse(
                dnsPayload = responseDns,
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort
            )

            tunOutput.write(responsePacket)
            tunOutput.flush()

        } catch (e: Exception) {
            Log.w(TAG, "DNS forward failed: ${e.message}")
        }
    }

    private fun wrapDnsResponse(
        dnsPayload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val udpLength = 8 + dnsPayload.size
        val totalLength = 20 + udpLength
        val buf = ByteBuffer.allocate(totalLength)

        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLength.toShort())
        buf.putShort(0)
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(17.toByte())
        buf.putShort(0)
        buf.put(srcIp)
        buf.put(dstIp)

        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLength.toShort())
        buf.putShort(0)

        buf.put(dnsPayload)

        val packet = buf.array()

        var sum = 0L
        for (i in 0 until 20 step 2) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = sum.inv().toInt() and 0xFFFF
        packet[10] = (checksum shr 8).toByte()
        packet[11] = (checksum and 0xFF).toByte()

        return packet
    }

    // -------------------------------------------------------------------------
    // Notifications
    // -------------------------------------------------------------------------

    private fun createNotificationChannels() {
        val vpnChannel = NotificationChannel(
            CHANNEL_ID,
            "DNS Filter Active",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Shows when Halal Filter DNS protection is active"
            setShowBadge(false)
        }

        val alertChannel = NotificationChannel(
            CHANNEL_ALERT_ID,
            "Protection Alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Alerts when DNS protection is unexpectedly disabled"
        }

        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(vpnChannel)
        manager.createNotificationChannel(alertChannel)
    }

    private fun buildNotification(totalQueries: Long, blockedQueries: Long): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val pendingOpen = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, HalalVpnService::class.java).apply {
            action = "STOP"
        }
        val pendingStop = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val contentText = if (totalQueries > 0) {
            "$blockedQueries blocked / $totalQueries queries"
        } else {
            "Protecting your privacy"
        }

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Halal Filter Active")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingOpen)
            .addAction(
                Notification.Action.Builder(
                    null, "Stop", pendingStop
                ).build()
            )
            .setOngoing(true)
            .build()
    }

    /**
     * Show a high-priority alert when VPN protection is lost unexpectedly
     * (system kill, another VPN app, battery optimization).
     */
    private fun showProtectionLostAlert() {
        val reopenIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingReopen = PendingIntent.getActivity(
            this, 2, reopenIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val alert = Notification.Builder(this, CHANNEL_ALERT_ID)
            .setContentTitle("Protection Disabled")
            .setContentText("Your DNS filter was stopped. Tap to re-enable.")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentIntent(pendingReopen)
            .setAutoCancel(true)
            .build()

        notificationManager?.notify(ALERT_NOTIFICATION_ID, alert)
    }
}
