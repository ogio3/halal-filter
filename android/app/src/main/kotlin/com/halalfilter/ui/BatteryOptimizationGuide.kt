package com.halalfilter.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryAlert
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * Detects OEM and shows device-specific instructions to disable aggressive
 * battery optimization that kills VPN services in the background.
 *
 * Based on https://dontkillmyapp.com data.
 */

data class OemGuide(
    val manufacturer: String,
    val title: String,
    val steps: List<String>,
    val settingsAction: String? = null
)

private val oemGuides = mapOf(
    "huawei" to OemGuide(
        manufacturer = "Huawei / Honor",
        title = "Huawei Battery Optimization",
        steps = listOf(
            "Open Settings > Battery > App Launch",
            "Find \"Halal Filter\" in the list",
            "Toggle OFF \"Manage automatically\"",
            "In the popup, enable ALL three switches:\n  • Auto-launch\n  • Secondary launch\n  • Run in background",
            "Tap OK to save"
        )
    ),
    "honor" to OemGuide(
        manufacturer = "Huawei / Honor",
        title = "Honor Battery Optimization",
        steps = listOf(
            "Open Settings > Battery > App Launch",
            "Find \"Halal Filter\" in the list",
            "Toggle OFF \"Manage automatically\"",
            "In the popup, enable ALL three switches:\n  • Auto-launch\n  • Secondary launch\n  • Run in background",
            "Tap OK to save"
        )
    ),
    "xiaomi" to OemGuide(
        manufacturer = "Xiaomi / Redmi / POCO",
        title = "Xiaomi Battery Settings",
        steps = listOf(
            "Open Settings > Apps > Manage apps",
            "Find \"Halal Filter\" and tap it",
            "Tap \"Autostart\" and enable it",
            "Go back, tap \"Battery saver\"",
            "Select \"No restrictions\"",
            "Also: in Recent Apps, swipe down on Halal Filter to LOCK it (padlock icon)"
        )
    ),
    "samsung" to OemGuide(
        manufacturer = "Samsung",
        title = "Samsung Battery Settings",
        steps = listOf(
            "Open Settings > Apps > Halal Filter",
            "Tap Battery",
            "Select \"Unrestricted\" (not \"Optimized\")",
            "Also: Settings > Device care > Battery > Background usage limits",
            "Make sure Halal Filter is NOT in the \"Sleeping apps\" or \"Deep sleeping apps\" lists"
        )
    ),
    "oppo" to OemGuide(
        manufacturer = "OPPO / Realme / OnePlus",
        title = "OPPO Battery Settings",
        steps = listOf(
            "Open Settings > Battery > More battery settings",
            "Tap \"Optimize battery use\"",
            "Find \"Halal Filter\" and select \"Don't optimize\"",
            "Also: Settings > Apps > Halal Filter > Battery > Allow background activity"
        )
    ),
    "vivo" to OemGuide(
        manufacturer = "Vivo / iQOO",
        title = "Vivo Battery Settings",
        steps = listOf(
            "Open Settings > Battery > Background power consumption",
            "Find \"Halal Filter\" and enable \"Allow background running\"",
            "Also: Settings > Apps > Halal Filter > Battery > Unrestricted"
        )
    ),
)

fun getOemGuide(): OemGuide? {
    val manufacturer = Build.MANUFACTURER.lowercase()
    return oemGuides.entries.firstOrNull { manufacturer.contains(it.key) }?.value
}

fun isBatteryOptimizationIgnored(context: Context): Boolean {
    val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    return pm.isIgnoringBatteryOptimizations(context.packageName)
}

private fun isPowerGenieInstalled(context: Context): Boolean {
    return try {
        context.packageManager.getPackageInfo("com.hihonor.powergenie", 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }
}

private fun openPowerGenieAppLaunch(context: Context): Boolean {
    return try {
        val intent = Intent().apply {
            component = ComponentName(
                "com.hihonor.powergenie",
                "com.hihonor.powergenie.ui.AppLaunchActivity"
            )
        }
        context.startActivity(intent)
        true
    } catch (_: Exception) {
        false
    }
}

@Composable
fun BatteryOptimizationCard(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val guide = remember { getOemGuide() }
    var isIgnored by remember { mutableStateOf(isBatteryOptimizationIgnored(context)) }

    // No guide for this OEM, or already optimized — show nothing
    if (guide == null && isIgnored) return

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isIgnored)
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
            else
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = if (isIgnored) Icons.Filled.CheckCircle
                    else Icons.Filled.BatteryAlert,
                    contentDescription = null,
                    tint = if (isIgnored) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.error
                )
                Text(
                    text = if (isIgnored) "Battery optimization disabled"
                    else "Background protection at risk",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }

            if (!isIgnored) {
                Text(
                    text = "Your device may stop the DNS filter when the screen is off. " +
                            "Disable battery optimization to keep protection running.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Android standard battery optimization request
                FilledTonalButton(
                    onClick = {
                        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                            data = Uri.parse("package:${context.packageName}")
                        }
                        context.startActivity(intent)
                        // Re-check after returning
                        isIgnored = isBatteryOptimizationIgnored(context)
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Disable Battery Optimization")
                }

                // OEM-specific guide
                if (guide != null) {
                    Text(
                        text = "${guide.manufacturer} users also need:",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    guide.steps.forEachIndexed { index, step ->
                        Text(
                            text = "${index + 1}. $step",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // PowerGenie-specific guidance for Honor devices
                if (isPowerGenieInstalled(context)) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                    Text(
                        text = "Honor PowerGenie detected",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "PowerGenie manages apps independently. Open App Launch settings " +
                                "and disable \"Manage automatically\" for Halal Filter.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedButton(
                        onClick = { openPowerGenieAppLaunch(context) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Open App Launch Settings")
                    }
                }

                // Always-on VPN guidance
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                Text(
                    text = "For best protection, enable Always-on VPN:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "Settings → Network & internet → VPN → Halal Filter → Always-on VPN ✓",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                TextButton(onClick = onDismiss) {
                    Text("Remind me later")
                }
            }
        }
    }
}
