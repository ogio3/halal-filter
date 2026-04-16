package com.halalfilter

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.halalfilter.bridge.NativeFilter
import com.halalfilter.ui.BlockedDomainEntry
import com.halalfilter.ui.DashboardState
import com.halalfilter.vpn.HalalVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow(DashboardState())
    val state: StateFlow<DashboardState> = _state.asStateFlow()

    private val app = application as HalalFilterApp
    private val handle = app.getOrCreateEngine()

    init {
        if (handle != 0L) {
            _state.update {
                it.copy(blocklistCount = NativeFilter.getBlocklistCount(handle))
            }
        }

        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                val vpnActive = HalalVpnService.isRunning
                if (handle != 0L && vpnActive) {
                    val total = NativeFilter.getTotalQueries(handle)
                    val blocked = NativeFilter.getBlockedQueries(handle)
                    val domainsJson = NativeFilter.getBlockedDomainsJson(handle, 20)
                    val domains = parseBlockedDomains(domainsJson)

                    _state.update {
                        it.copy(
                            isActive = true,
                            totalQueries = total,
                            blockedQueries = blocked,
                            blockedDomains = domains
                        )
                    }
                } else {
                    _state.update { it.copy(isActive = vpnActive) }
                }
                delay(2000)
            }
        }
    }

    fun getEngineHandle(): Long = handle

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
