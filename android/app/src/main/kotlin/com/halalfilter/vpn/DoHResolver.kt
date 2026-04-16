package com.halalfilter.vpn

import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * DNS resolver using protected UDP to Quad9.
 *
 * The socket is protected from VPN routing loop via VpnService.protect(),
 * so DNS queries bypass our own TUN interface and reach the upstream directly.
 *
 * Thread safety: all socket operations are synchronized to prevent races
 * between resolve() (packet loop coroutine) and close() (stopVpn).
 */
class DoHResolver(private val vpnService: VpnService) {

    companion object {
        private const val TAG = "DoHResolver"
        private val UPSTREAM_DNS = InetAddress.getByName("9.9.9.9")
        private const val DNS_PORT = 53
        private const val SOCKET_TIMEOUT_MS = 3000
    }

    private val lock = Any()
    private val recvBuffer = ByteArray(4096)
    private var socket: DatagramSocket? = null

    fun resolve(dnsPayload: ByteArray): ByteArray? {
        val sock = synchronized(lock) { getOrCreateSocket() } ?: return null
        return try {
            val sendPacket = DatagramPacket(dnsPayload, dnsPayload.size, UPSTREAM_DNS, DNS_PORT)
            sock.send(sendPacket)

            val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)
            sock.receive(recvPacket)

            // Validate response source to prevent DNS spoofing
            if (recvPacket.address != UPSTREAM_DNS || recvPacket.port != DNS_PORT) {
                Log.w(TAG, "DNS response from unexpected source")
                return null
            }

            val response = recvBuffer.copyOf(recvPacket.length)

            // Validate DNS transaction ID matches the query
            if (response.size < 4 || dnsPayload.size < 2) {
                return null
            }
            val queryTxId = ((dnsPayload[0].toInt() and 0xFF) shl 8) or
                    (dnsPayload[1].toInt() and 0xFF)
            val responseTxId = ((response[0].toInt() and 0xFF) shl 8) or
                    (response[1].toInt() and 0xFF)
            if (responseTxId != queryTxId) {
                Log.w(TAG, "DNS TX ID mismatch")
                return null
            }

            // Validate QR bit = 1 (response, not another query)
            if ((response[2].toInt() and 0x80) == 0) {
                Log.w(TAG, "DNS response has QR=0 (not a response)")
                return null
            }

            response
        } catch (e: Exception) {
            Log.w(TAG, "DNS resolution failed, resetting socket: ${e.message}")
            synchronized(lock) {
                socket?.close()
                socket = null
            }
            null
        }
    }

    fun close() {
        synchronized(lock) {
            socket?.close()
            socket = null
        }
    }

    private fun getOrCreateSocket(): DatagramSocket? {
        socket?.let { if (!it.isClosed) return it }

        return try {
            DatagramSocket().also { s ->
                if (!vpnService.protect(s)) {
                    Log.e(TAG, "Failed to protect DNS socket from VPN routing loop")
                    s.close()
                    return null
                }
                s.soTimeout = SOCKET_TIMEOUT_MS
                socket = s
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create DNS socket: ${e.message}")
            null
        }
    }
}
