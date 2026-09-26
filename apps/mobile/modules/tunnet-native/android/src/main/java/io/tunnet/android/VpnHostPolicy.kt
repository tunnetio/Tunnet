package io.tunnet.android

/**
 * Serialized Service command policy. Actual runtime state is native;
 * [wanted] is persisted user intent.
 */
object VpnHostPolicy {
    const val ACTION_CONNECT = "io.tunnet.android.CONNECT"
    const val ACTION_DISCONNECT = "io.tunnet.android.DISCONNECT"

    enum class Command {
        Attach,
        Stop,
    }

    data class Decision(
        val command: Command,
        val sticky: Boolean,
        val wanted: Boolean,
        val invite: String?,
    )

    fun decide(action: String?, invite: String?, wanted: Boolean): Decision {
        val trimmedInvite = invite?.trim()?.takeIf { it.isNotEmpty() }
        return when (action) {
            ACTION_DISCONNECT -> Decision(
                command = Command.Stop,
                sticky = false,
                wanted = false,
                invite = null,
            )
            ACTION_CONNECT -> Decision(
                command = Command.Attach,
                sticky = true,
                wanted = true,
                invite = trimmedInvite,
            )
            else -> {
                if (wanted) {
                    Decision(
                        command = Command.Attach,
                        sticky = true,
                        wanted = true,
                        invite = null,
                    )
                } else {
                    Decision(
                        command = Command.Stop,
                        sticky = false,
                        wanted = false,
                        invite = null,
                    )
                }
            }
        }
    }
}
