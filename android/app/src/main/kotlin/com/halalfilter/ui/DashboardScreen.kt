package com.halalfilter.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.ShieldMoon
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import com.halalfilter.data.TrackerInfo
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class BlockedDomainEntry(
    val domain: String,
    val count: Long
)

data class DashboardState(
    val isActive: Boolean = false,
    val totalQueries: Long = 0,
    val blockedQueries: Long = 0,
    val blocklistCount: Int = 0,
    val blockedDomains: List<BlockedDomainEntry> = emptyList(),
    val needsVpnPermission: Boolean = false
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    state: DashboardState,
    onToggleFilter: () -> Unit,
    onDiagnose: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val shieldScale by animateFloatAsState(
        targetValue = if (state.isActive) 1.0f else 0.9f,
        label = "shieldScale"
    )
    val shieldColor by animateColorAsState(
        targetValue = if (state.isActive)
            MaterialTheme.colorScheme.primary
        else
            MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
        label = "shieldColor"
    )

    val context = LocalContext.current
    val trackerInfo = remember { try { TrackerInfo(context) } catch (_: Exception) { null } }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(vertical = 32.dp)
    ) {
        // Shield + Toggle
        item {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Icon(
                    imageVector = if (state.isActive)
                        Icons.Filled.Shield else Icons.Filled.ShieldMoon,
                    contentDescription = if (state.isActive) "Protected" else "Unprotected",
                    modifier = Modifier
                        .size(120.dp)
                        .scale(shieldScale),
                    tint = shieldColor
                )

                Text(
                    text = if (state.isActive) "Protected" else "Unprotected",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = shieldColor
                )

                FilledTonalButton(
                    onClick = onToggleFilter,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.filledTonalButtonColors(
                        containerColor = if (state.isActive)
                            MaterialTheme.colorScheme.errorContainer
                        else
                            MaterialTheme.colorScheme.primaryContainer
                    )
                ) {
                    Text(
                        text = if (state.isActive) "Disable Protection" else "Enable Protection",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        // Stats Cards
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatCard(
                    title = "Queries",
                    value = formatCount(state.totalQueries),
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Blocked",
                    value = formatCount(state.blockedQueries),
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Rules",
                    value = formatCount(state.blocklistCount.toLong()),
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Battery optimization warning (OEM-specific)
        item {
            var showBatteryGuide by remember { mutableStateOf(true) }
            if (showBatteryGuide) {
                BatteryOptimizationCard(
                    onDismiss = { showBatteryGuide = false }
                )
            }
        }

        // Block percentage
        if (state.totalQueries > 0) {
            item {
                val pct = (state.blockedQueries * 100.0 / state.totalQueries)
                val progress = (state.blockedQueries.toFloat() / state.totalQueries.toFloat())
                    .coerceIn(0f, 1f)

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "Block Rate",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = String.format("%.1f%%", pct),
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold
                        )
                        LinearProgressIndicator(
                            progress = { progress },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(8.dp),
                            trackColor = MaterialTheme.colorScheme.surfaceVariant,
                        )
                    }
                }
            }
        }

        // Diagnose button
        if (state.blockedDomains.isNotEmpty()) {
            item {
                OutlinedButton(
                    onClick = onDiagnose,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(
                        Icons.Filled.Shield,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Why isn't my app working?")
                }
            }
        }

        // Blocked Domains List
        if (state.blockedDomains.isNotEmpty()) {
            item {
                Text(
                    text = "Blocked Connections",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                )
            }

            items(state.blockedDomains) { entry ->
                BlockedDomainRow(entry, trackerInfo)
            }
        }
    }
}

@Composable
private fun StatCard(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.onSurface
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = color,
                textAlign = TextAlign.Center
            )
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun BlockedDomainRow(entry: BlockedDomainEntry, trackerInfo: TrackerInfo?) {
    val tracker = trackerInfo?.lookup(entry.domain)
    val severity = tracker?.let { trackerInfo.getSeverity(it.severity) }
    val severityColor = when (tracker?.severity) {
        "critical" -> MaterialTheme.colorScheme.error
        "high" -> Color(0xFFE65100)
        else -> Color(0xFFFF8F00)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = severityColor.copy(alpha = 0.08f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // Header: tracker name + count badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = tracker?.name ?: entry.domain,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = severityColor
                    )
                    if (tracker != null) {
                        Text(
                            text = entry.domain,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Surface(
                    shape = CircleShape,
                    color = severityColor.copy(alpha = 0.15f)
                ) {
                    Text(
                        text = formatCount(entry.count),
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = severityColor
                    )
                }
            }

            // Severity badge
            if (severity != null) {
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = severityColor.copy(alpha = 0.12f)
                ) {
                    Text(
                        text = severity.labelEn,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = severityColor
                    )
                }
            }

            // Description
            if (tracker != null) {
                Text(
                    text = tracker.descriptionEn,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Data types
            val dataTypes = trackerInfo?.formatDataTypes(entry.domain)
            if (dataTypes != null) {
                Text(
                    text = "Collecting: $dataTypes",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }

            // Data pipeline
            if (tracker != null && tracker.pipeline.isNotEmpty()) {
                Text(
                    text = "→ ${tracker.pipeline}",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = severityColor.copy(alpha = 0.8f)
                )
            }
        }
    }
}

private fun formatCount(n: Long): String = when {
    n >= 1_000_000 -> String.format("%.1fM", n / 1_000_000.0)
    n >= 1_000 -> String.format("%.1fK", n / 1_000.0)
    else -> n.toString()
}
