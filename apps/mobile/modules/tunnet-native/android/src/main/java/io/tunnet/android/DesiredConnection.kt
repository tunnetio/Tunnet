package io.tunnet.android

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * Android-only user intent: stay connected until the user (or VPN revoke)
 * turns it off. Independent of [io.tunnet.android.wire.Snapshot] lifecycle.
 */
class DesiredConnection(private val store: FlagStore) {
    var wanted: Boolean
        get() = store.get()
        set(value) = store.set(value)

    companion object {
        private const val PREFS = "tunnet-host"
        private const val KEY = "wanted"

        fun of(context: Context): DesiredConnection = DesiredConnection(
            PrefsFlagStore(
                context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE),
                KEY,
            ),
        )
    }
}

interface FlagStore {
    fun get(): Boolean
    fun set(value: Boolean)
}

class MemoryFlagStore(initial: Boolean = false) : FlagStore {
    @Volatile
    private var value = initial

    override fun get(): Boolean = value
    override fun set(value: Boolean) {
        this.value = value
    }
}

private class PrefsFlagStore(
    private val prefs: SharedPreferences,
    private val key: String,
) : FlagStore {
    override fun get(): Boolean = prefs.getBoolean(key, false)
    override fun set(value: Boolean) {
        prefs.edit { putBoolean(key, value) }
    }
}
