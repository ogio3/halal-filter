package com.halalfilter.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.halalfilter.data.TrackerInfo

/**
 * Diagnostic screen: "Why isn't this app working?"
 *
 * Shows which tracker connections were blocked for a specific app,
 * explains why in plain language, and lets the user selectively
 * allow specific trackers if they accept the risk.
 */

data class BlockedConnection(
    val domain: String,
    val trackerName: String,
    val severity: String,
    val description: String,
    val dataCollected: String,
    val pipeline: String,
    val isAllowed: Boolean = false
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticSheet(
    blockedDomains: List<BlockedDomainEntry>,
    onAllowDomain: (String) -> Unit,
    onBlockDomain: (String) -> Unit,
    onRequestAudit: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val trackerInfo = remember { try { TrackerInfo(context) } catch (_: Exception) { null } }

    // Group blocked domains by whether we have info about them
    val knownTrackers = blockedDomains.mapNotNull { entry ->
        val tracker = trackerInfo?.lookup(entry.domain)
        if (tracker != null) {
            BlockedConnection(
                domain = entry.domain,
                trackerName = tracker.name,
                severity = tracker.severity,
                description = tracker.descriptionEn,
                dataCollected = trackerInfo.formatDataTypes(entry.domain) ?: "",
                pipeline = tracker.pipeline
            )
        } else null
    }

    val unknownDomains = blockedDomains.filter { entry ->
        trackerInfo?.lookup(entry.domain) == null
    }

    LazyColumn(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 24.dp)
    ) {
        // Header
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Troubleshoot,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        "Connection Diagnosis",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
                Text(
                    "Halal Filter blocked the following connections to protect your privacy. " +
                            "You can allow specific connections if you accept the risk.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                HorizontalDivider(modifier = Modifier.padding(top = 8.dp))
            }
        }

        // Known trackers with allow/block toggle
        if (knownTrackers.isNotEmpty()) {
            item {
                Text(
                    "Identified Trackers",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            items(knownTrackers) { connection ->
                DiagnosticTrackerCard(
                    connection = connection,
                    onAllow = { onAllowDomain(connection.domain) },
                    onBlock = { onBlockDomain(connection.domain) }
                )
            }
        }

        // Unknown domains
        if (unknownDomains.isNotEmpty()) {
            item {
                Text(
                    "Other Blocked Connections",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp)
                )
                Text(
                    "These domains were blocked but haven't been analyzed yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            items(unknownDomains) { entry ->
                UnknownDomainCard(
                    domain = entry.domain,
                    count = entry.count,
                    onAllow = { onAllowDomain(entry.domain) }
                )
            }
        }

        // Request audit section
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            Icons.Filled.Science,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            "Request App Analysis",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Text(
                        "Is an app not working and you're not sure why? " +
                                "Request a detailed privacy analysis. " +
                                "We'll examine the app and add it to our database " +
                                "(usually within 24 hours).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    var appName by remember { mutableStateOf("") }
                    OutlinedTextField(
                        value = appName,
                        onValueChange = { appName = it },
                        label = { Text("App name (e.g., Muslim Pro)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    FilledTonalButton(
                        onClick = {
                            if (appName.isNotBlank()) {
                                onRequestAudit(appName)
                                appName = ""
                            }
                        },
                        enabled = appName.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.Send, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Request Analysis")
                    }
                }
            }
        }
    }
}

@Composable
private fun DiagnosticTrackerCard(
    connection: BlockedConnection,
    onAllow: () -> Unit,
    onBlock: () -> Unit
) {
    val severityColor = when (connection.severity) {
        "critical" -> MaterialTheme.colorScheme.error
        "high" -> Color(0xFFE65100)
        else -> Color(0xFFFF8F00)
    }
    var isAllowed by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isAllowed)
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            else
                severityColor.copy(alpha = 0.08f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        connection.trackerName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (isAllowed) MaterialTheme.colorScheme.onSurfaceVariant
                        else severityColor
                    )
                    Text(
                        connection.domain,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                // Allow/Block toggle
                if (isAllowed) {
                    FilledTonalButton(
                        onClick = { isAllowed = false; onBlock() },
                        colors = ButtonDefaults.filledTonalButtonColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    ) {
                        Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Re-block", style = MaterialTheme.typography.labelSmall)
                    }
                } else {
                    OutlinedButton(
                        onClick = { isAllowed = true; onAllow() }
                    ) {
                        Text("Allow", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }

            if (!isAllowed) {
                // Description
                Text(
                    connection.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Data collected
                if (connection.dataCollected.isNotEmpty()) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(
                            Icons.Filled.DataUsage,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Collecting: ${connection.dataCollected}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // Pipeline
                if (connection.pipeline.isNotEmpty()) {
                    Text(
                        "→ ${connection.pipeline}",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = severityColor.copy(alpha = 0.8f)
                    )
                }
            } else {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFFFFF3E0)
                ) {
                    Row(
                        modifier = Modifier.padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = Color(0xFFE65100)
                        )
                        Text(
                            "This connection is now allowed. Your data may be collected.",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFFE65100)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun UnknownDomainCard(
    domain: String,
    count: Long,
    onAllow: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    domain,
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    "Blocked $count times • Not yet analyzed",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            OutlinedButton(onClick = onAllow) {
                Text("Allow", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
