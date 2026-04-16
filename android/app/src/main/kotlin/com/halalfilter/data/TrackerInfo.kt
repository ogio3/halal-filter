package com.halalfilter.data

import android.content.Context
import org.json.JSONObject

/**
 * Provides human-readable descriptions of blocked tracker domains.
 *
 * Loaded from tracker_descriptions.json in assets. Maps domain names
 * to their category, severity, and plain-language explanation of what
 * data they collect and who receives it.
 */
class TrackerInfo(context: Context) {

    data class Tracker(
        val domain: String,
        val name: String,
        val category: String,
        val severity: String,
        val descriptionEn: String,
        val descriptionJa: String,
        val foundIn: List<String>,
        val dataCollected: List<String>,
        val pipeline: String
    )

    data class Category(
        val nameEn: String,
        val nameJa: String,
        val color: String
    )

    data class Severity(
        val labelEn: String,
        val labelJa: String,
        val color: String
    )

    private val trackers: Map<String, Tracker>
    private val categories: Map<String, Category>
    private val severities: Map<String, Severity>

    init {
        val json = context.assets.open("tracker_descriptions.json")
            .bufferedReader().use { it.readText() }
        val root = JSONObject(json)

        // Parse trackers
        val trackersObj = root.getJSONObject("trackers")
        trackers = buildMap {
            for (domain in trackersObj.keys()) {
                val t = trackersObj.getJSONObject(domain)
                val foundIn = mutableListOf<String>()
                val foundInArr = t.getJSONArray("found_in")
                for (i in 0 until foundInArr.length()) foundIn.add(foundInArr.getString(i))

                val dataCollected = mutableListOf<String>()
                val dataArr = t.getJSONArray("data_collected")
                for (i in 0 until dataArr.length()) dataCollected.add(dataArr.getString(i))

                put(domain, Tracker(
                    domain = domain,
                    name = t.getString("name"),
                    category = t.getString("category"),
                    severity = t.getString("severity"),
                    descriptionEn = t.getString("description_en"),
                    descriptionJa = t.getString("description_ja"),
                    foundIn = foundIn,
                    dataCollected = dataCollected,
                    pipeline = t.getString("pipeline")
                ))
            }
        }

        // Parse categories
        val catsObj = root.getJSONObject("categories")
        categories = buildMap {
            for (key in catsObj.keys()) {
                val c = catsObj.getJSONObject(key)
                put(key, Category(
                    nameEn = c.getString("name_en"),
                    nameJa = c.getString("name_ja"),
                    color = c.getString("color")
                ))
            }
        }

        // Parse severities
        val sevObj = root.getJSONObject("severity_levels")
        severities = buildMap {
            for (key in sevObj.keys()) {
                val s = sevObj.getJSONObject(key)
                put(key, Severity(
                    labelEn = s.getString("label_en"),
                    labelJa = s.getString("label_ja"),
                    color = s.getString("color")
                ))
            }
        }
    }

    /**
     * Look up tracker info for a blocked domain.
     * Walks up the domain hierarchy (e.g., api.xmode.io → xmode.io).
     */
    fun lookup(domain: String): Tracker? {
        var d = domain.lowercase().trimEnd('.')
        while (true) {
            trackers[d]?.let { return it }
            val dot = d.indexOf('.')
            if (dot < 0) break
            d = d.substring(dot + 1)
        }
        return null
    }

    fun getCategory(categoryId: String): Category? = categories[categoryId]
    fun getSeverity(severityId: String): Severity? = severities[severityId]

    /**
     * Format a human-readable explanation for a non-technical user.
     * Example: "Blocked X-Mode (Location Data Broker) — Sells your GPS
     * location to US military contractors."
     */
    fun formatBlockedExplanation(domain: String): String? {
        val tracker = lookup(domain) ?: return null
        val cat = categories[tracker.category]
        val catName = cat?.nameEn ?: tracker.category
        return "${tracker.name} ($catName) — ${tracker.descriptionEn}"
    }

    /**
     * Format for Japanese users.
     */
    fun formatBlockedExplanationJa(domain: String): String? {
        val tracker = lookup(domain) ?: return null
        val cat = categories[tracker.category]
        val catName = cat?.nameJa ?: tracker.category
        return "${tracker.name}（$catName）— ${tracker.descriptionJa}"
    }

    /**
     * Get data types collected by a tracker, formatted for display.
     */
    fun formatDataTypes(domain: String): String? {
        val tracker = lookup(domain) ?: return null
        return tracker.dataCollected.joinToString(", ") { type ->
            when (type) {
                "gps_location" -> "GPS location"
                "wifi_bssid" -> "WiFi network ID"
                "device_id" -> "Device ID"
                "device_fingerprint" -> "Device fingerprint"
                "timestamp" -> "Timestamp"
                "movement_patterns" -> "Movement patterns"
                "cell_tower_data" -> "Cell tower data"
                "network_measurements" -> "Network data"
                "app_usage" -> "App usage"
                "halal_food_scans" -> "Halal food scans"
                "browsing_behavior" -> "Browsing behavior"
                "messaging_metadata" -> "Message metadata"
                "device_info" -> "Device info"
                "financial_data" -> "Financial data"
                "app_events" -> "App events"
                "quran_reading_chapters" -> "Quran reading"
                "prayer_times" -> "Prayer times"
                "advertising_id" -> "Advertising ID"
                "app_install_attribution" -> "Install tracking"
                "usage_patterns" -> "Usage patterns"
                "profile_data" -> "Profile data"
                "interaction_patterns" -> "Interactions"
                "screen_views" -> "Screen views"
                "session_data" -> "Session data"
                "ad_interaction" -> "Ad clicks"
                "aggregated_location_data" -> "Location data"
                else -> type.replace('_', ' ')
            }
        }
    }
}
