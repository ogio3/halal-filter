package com.halalfilter

import android.Manifest
import android.app.Activity
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
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
import androidx.lifecycle.viewmodel.compose.viewModel
import com.halalfilter.bridge.NativeFilter
import com.halalfilter.ui.DashboardScreen
import com.halalfilter.ui.DiagnosticSheet
import com.halalfilter.ui.theme.HalalFilterTheme
import com.halalfilter.vpn.HalalVpnService

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

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            Log.w(TAG, "Notification permission denied — protection alerts will not be shown")
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request notification permission on Android 13+ (required for circuit breaker alerts)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            HalalFilterTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val viewModel: DashboardViewModel = viewModel()
                    val state by viewModel.state.collectAsState()
                    val handle = viewModel.getEngineHandle()

                    var showDiagnostic by remember { mutableStateOf(false) }

                    DashboardScreen(
                        state = state,
                        onToggleFilter = { toggleVpn() },
                        onDiagnose = { showDiagnostic = true }
                    )

                    if (showDiagnostic) {
                        ModalBottomSheet(
                            onDismissRequest = { showDiagnostic = false }
                        ) {
                            val prefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)

                            DiagnosticSheet(
                                blockedDomains = state.blockedDomains,
                                onAllowDomain = { domain ->
                                    if (handle != 0L) {
                                        NativeFilter.addAllowlist(handle, domain)
                                        val set = prefs.getStringSet("allowed_domains", mutableSetOf())
                                            ?.toMutableSet() ?: mutableSetOf()
                                        set.add(domain)
                                        prefs.edit().putStringSet("allowed_domains", set).apply()
                                    }
                                },
                                onBlockDomain = { domain ->
                                    if (handle != 0L) {
                                        NativeFilter.removeAllowlist(handle, domain)
                                        val set = prefs.getStringSet("allowed_domains", mutableSetOf())
                                            ?.toMutableSet() ?: mutableSetOf()
                                        set.remove(domain)
                                        prefs.edit().putStringSet("allowed_domains", set).apply()
                                    }
                                },
                                onRequestAudit = { appName ->
                                    val auditPrefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
                                    val existing = auditPrefs.getStringSet("audit_requests", mutableSetOf())
                                        ?.toMutableSet() ?: mutableSetOf()
                                    existing.add(appName)
                                    auditPrefs.edit().putStringSet("audit_requests", existing).apply()
                                    Log.i(TAG, "Audit request saved: $appName")
                                },
                                onDismiss = { showDiagnostic = false },
                                isDomainAllowed = { domain ->
                                    handle != 0L && NativeFilter.isAllowed(handle, domain)
                                }
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Detect silent VPN death (OOM kill, battery optimization, Doze).
        // SharedPreferences vpn_enabled stays true but the service is gone.
        val prefs = getSharedPreferences("halal_filter", Context.MODE_PRIVATE)
        if (prefs.getBoolean("vpn_enabled", false) && !HalalVpnService.isRunning) {
            Log.w(TAG, "VPN was expected to be running but isn't — likely killed by system")
            prefs.edit().putBoolean("vpn_enabled", false).apply()

            val nm = getSystemService(NotificationManager::class.java)
            val alert = android.app.Notification.Builder(this, HalalVpnService.CHANNEL_ALERT_ID)
                .setContentTitle("Protection Disabled")
                .setContentText("DNS protection was stopped by the system. Tap to re-enable.")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentIntent(android.app.PendingIntent.getActivity(
                    this, 2,
                    Intent(this, MainActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    },
                    android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
                ))
                .setAutoCancel(true)
                .build()
            nm.notify(HalalVpnService.ALERT_NOTIFICATION_ID, alert)
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

    private fun isVpnActive(): Boolean = HalalVpnService.isRunning
}
