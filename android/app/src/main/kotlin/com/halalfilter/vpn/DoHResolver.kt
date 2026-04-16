package com.halalfilter.vpn

import android.net.VpnService
import android.util.Log
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * DNS resolver with DoH (primary) and protected UDP (fallback).
 *
 * DoH encrypts queries via HTTPS (RFC 8484) to Quad9.
 * If DoH fails (connectivity issues), falls back to plain UDP via
 * a VPN-protected socket (still prevents VPN routing loop).
 */
class DoHResolver(private val vpnService: VpnService) {

    companion object {
        private const val TAG = "DoHResolver"
        private const val DOH_URL = "https://dns.quad9.net/dns-query"
        private val DNS_MESSAGE_TYPE = "application/dns-message".toMediaType()
        private const val CONNECT_TIMEOUT_MS = 3000L
        private const val READ_TIMEOUT_MS = 3000L

        // Fallback plain DNS (protected from VPN loop)
        private val UPSTREAM_DNS = InetAddress.getByName("9.9.9.9")
        private const val DNS_PORT = 53
    }

    private val protectedFactory = ProtectedSocketFactory(vpnService)

    private val client: OkHttpClient by lazy {
        val defaultSslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory

        OkHttpClient.Builder()
            .socketFactory(protectedFactory)
            .sslSocketFactory(
                ProtectedSSLSocketFactory(vpnService, defaultSslFactory),
                javax.net.ssl.X509TrustManager::class.java.let {
                    val tmf = javax.net.ssl.TrustManagerFactory.getInstance(
                        javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
                    )
                    tmf.init(null as? java.security.KeyStore)
                    tmf.trustManagers.first() as javax.net.ssl.X509TrustManager
                }
            )
            .dns(StaticDns(mapOf(
                "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
            )))
            .connectTimeout(CONNECT_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            .readTimeout(READ_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            .build()
    }

    /**
     * Resolve via protected plain UDP (VPN-loop safe).
     *
     * DoH (DNS-over-HTTPS) is architecturally complex in a VPN context
     * because the HTTPS connection itself needs DNS and routing that
     * bypasses the VPN. For v0.1, we use protected UDP to Quad9 which
     * is reliable and avoids the chicken-and-egg problem entirely.
     * DoH will be implemented in a future version using a dedicated
     * network connection outside the VPN tunnel.
     */
    fun resolve(dnsPayload: ByteArray): ByteArray? {
        return resolvePlainUdp(dnsPayload)
    }

    private fun resolveDoH(dnsPayload: ByteArray): ByteArray? {
        return try {
            val request = Request.Builder()
                .url(DOH_URL)
                .post(dnsPayload.toRequestBody(DNS_MESSAGE_TYPE))
                .header("Accept", "application/dns-message")
                .build()

            val response = client.newCall(request).execute()
            response.use {
                if (it.isSuccessful) it.body?.bytes() else null
            }
        } catch (e: Exception) {
            Log.d(TAG, "DoH failed, falling back to UDP: ${e.message}")
            null
        }
    }

    private fun resolvePlainUdp(dnsPayload: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        return try {
            if (!vpnService.protect(socket)) {
                Log.e(TAG, "Failed to protect DNS socket from VPN routing loop")
                return null
            }
            socket.soTimeout = 5000

            val sendPacket = DatagramPacket(
                dnsPayload, dnsPayload.size, UPSTREAM_DNS, DNS_PORT
            )
            socket.send(sendPacket)

            val recvBuffer = ByteArray(4096)
            val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)
            socket.receive(recvPacket)

            recvBuffer.copyOf(recvPacket.length)
        } catch (e: Exception) {
            Log.w(TAG, "DNS resolution failed: ${e.message}", e)
            null
        } finally {
            socket.close()
        }
    }

    private class StaticDns(
        private val overrides: Map<String, List<String>>
    ) : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val ips = overrides[hostname]
            return if (ips != null) {
                ips.map { InetAddress.getByName(it) }
            } else {
                Dns.SYSTEM.lookup(hostname)
            }
        }
    }

    private class ProtectedSocketFactory(
        private val vpnService: VpnService
    ) : SocketFactory() {

        override fun createSocket(): Socket {
            return Socket().also { vpnService.protect(it) }
        }

        override fun createSocket(host: String, port: Int): Socket {
            return Socket().also {
                vpnService.protect(it)
                it.connect(InetSocketAddress(host, port))
            }
        }

        override fun createSocket(
            host: String, port: Int,
            localHost: InetAddress, localPort: Int
        ): Socket {
            return Socket().also {
                vpnService.protect(it)
                it.bind(InetSocketAddress(localHost, localPort))
                it.connect(InetSocketAddress(host, port))
            }
        }

        override fun createSocket(host: InetAddress, port: Int): Socket {
            return Socket().also {
                vpnService.protect(it)
                it.connect(InetSocketAddress(host, port))
            }
        }

        override fun createSocket(
            address: InetAddress, port: Int,
            localAddress: InetAddress, localPort: Int
        ): Socket {
            return Socket().also {
                vpnService.protect(it)
                it.bind(InetSocketAddress(localAddress, localPort))
                it.connect(InetSocketAddress(address, port))
            }
        }
    }

    /**
     * SSL socket factory that protects the underlying TCP socket from VPN loop.
     */
    private class ProtectedSSLSocketFactory(
        private val vpnService: VpnService,
        private val delegate: SSLSocketFactory
    ) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(): Socket {
            return (delegate.createSocket() as SSLSocket).also {
                vpnService.protect(it)
            }
        }

        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
            vpnService.protect(s)
            return delegate.createSocket(s, host, port, autoClose)
        }

        override fun createSocket(host: String, port: Int): Socket {
            val socket = Socket()
            vpnService.protect(socket)
            socket.connect(InetSocketAddress(host, port))
            return delegate.createSocket(socket, host, port, true)
        }

        override fun createSocket(
            host: String, port: Int,
            localHost: InetAddress, localPort: Int
        ): Socket {
            val socket = Socket()
            vpnService.protect(socket)
            socket.bind(InetSocketAddress(localHost, localPort))
            socket.connect(InetSocketAddress(host, port))
            return delegate.createSocket(socket, host, port, true)
        }

        override fun createSocket(host: InetAddress, port: Int): Socket {
            val socket = Socket()
            vpnService.protect(socket)
            socket.connect(InetSocketAddress(host, port))
            return delegate.createSocket(socket, host.hostAddress, port, true)
        }

        override fun createSocket(
            address: InetAddress, port: Int,
            localAddress: InetAddress, localPort: Int
        ): Socket {
            val socket = Socket()
            vpnService.protect(socket)
            socket.bind(InetSocketAddress(localAddress, localPort))
            socket.connect(InetSocketAddress(address, port))
            return delegate.createSocket(socket, address.hostAddress, port, true)
        }
    }
}
