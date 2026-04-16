package com.halalfilter

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import com.halalfilter.bridge.NativeFilter
import com.halalfilter.ui.BlockedDomainEntry
import com.halalfilter.ui.DashboardScreen
import com.halalfilter.ui.DashboardState
import com.halalfilter.ui.DiagnosticSheet
import com.halalfilter.ui.theme.HalalFilterTheme
import com.halalfilter.vpn.HalalVpnService
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import org.json.JSONArray

class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Log.w(TAG, "VPN permission denied by user")
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            HalalFilterTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val state by produceState(DashboardState()) {
                        val app = application as HalalFilterApp
                        val handle = app.getOrCreateEngine()

                        // Update blocklist count once
                        if (handle != 0L) {
                            value = value.copy(
                                blocklistCount = NativeFilter.getBlocklistCount(handle)
                            )
                        }

                        // Poll stats every 2 seconds while active
                        while (isActive) {
                            val vpnActive = isVpnActive()
                            value = if (handle != 0L && vpnActive) {
                                val total = NativeFilter.getTotalQueries(handle)
                                val blocked = NativeFilter.getBlockedQueries(handle)
                                val domainsJson = NativeFilter.getBlockedDomainsJson(handle, 20)
                                val domains = parseBlockedDomains(domainsJson)

                                value.copy(
                                    isActive = true,
                                    totalQueries = total,
                                    blockedQueries = blocked,
                                    blockedDomains = domains
                                )
                            } else {
                                value.copy(isActive = vpnActive)
                            }
                            delay(2000)
                        }
                    }

                    var showDiagnostic by remember { mutableStateOf(false) }

                    DashboardScreen(
                        state = state,
                        onToggleFilter = { toggleVpn() },
                        onDiagnose = { showDiagnostic = true }
                    )

                    if (showDiagnostic) {
                        val app = application as HalalFilterApp
                        val handle = app.getEngineHandle()

                        ModalBottomSheet(
                            onDismissRequest = { showDiagnostic = false }
                        ) {
                            DiagnosticSheet(
                                blockedDomains = state.blockedDomains,
                                onAllowDomain = { domain ->
                                    if (handle != 0L) {
                                        NativeFilter.addAllowlist(handle, domain)
                                    }
                                },
                                onBlockDomain = { domain ->
                                    if (handle != 0L) {
                                        NativeFilter.removeAllowlist(handle, domain)
                                    }
                                },
                                onRequestAudit = { appName ->
                                    Log.i(TAG, "Audit requested for: $appName")
                                    // TODO: Send to backend or store locally
                                },
                                onDismiss = { showDiagnostic = false }
                            )
                        }
                    }
                }
            }
        }
    }

    private fun toggleVpn() {
        if (isVpnActive()) {
            stopVpnService()
        } else {
            requestVpnPermission()
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // Already authorized
            startVpnService()
        }
    }

    private fun startVpnService() {
        val prefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("vpn_enabled", true).apply()

        val intent = Intent(this, HalalVpnService::class.java)
        startForegroundService(intent)
        Log.i(TAG, "VPN service started")
    }

    private fun stopVpnService() {
        val prefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("vpn_enabled", false).apply()

        val intent = Intent(this, HalalVpnService::class.java).apply {
            action = "STOP"
        }
        startService(intent)
        Log.i(TAG, "VPN service stop requested")
    }

    private fun isVpnActive(): Boolean {
        return try {
            val cm = getSystemService(android.net.ConnectivityManager::class.java)
            val activeNetwork = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
        } catch (e: SecurityException) {
            // Fallback: check SharedPreferences
            val prefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
            prefs.getBoolean("vpn_enabled", false)
        }
    }

    private fun parseBlockedDomains(json: String): List<BlockedDomainEntry> {
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                BlockedDomainEntry(
                    domain = obj.getString("domain"),
                    count = obj.getLong("count")
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
