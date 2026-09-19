package io.tunnet.android

import android.os.ParcelFileDescriptor

object TunnelFd {
    fun detachOrClose(pfd: ParcelFileDescriptor): Int = try {
        pfd.detachFd()
    } catch (t: Throwable) {
        pfd.close()
        throw t
    }
}
