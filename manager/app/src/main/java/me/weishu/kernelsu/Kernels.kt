package me.weishu.kernelsu

import android.system.Os

/**
 * @author weishu
 * @date 2022/12/10.
 */

data class KernelVersion(val major: Int, val patchLevel: Int, val subLevel: Int) {
    override fun toString(): String {
        return "$major.$patchLevel.$subLevel"
    }

    fun isGKI(): Boolean {

        // 4.19-research-fork: this APK is forked for use with KernelSU-compat
        // patches on Linux 4.19-cip running on Xiaomi alioth (Redmi K40 /
        // POCO F3 / Mi 11X). The actual KSU functionality is gated on the
        // kernel module being loaded (detectable via the existing
        // ksud↔kernel ioctl), NOT on the kernel version string.
        //
        // For 4.19+ kernels with our compat patches, claim "supported" so
        // the rest of the app exercises real status checks.
        // Original GKI check below for reference:
        //   if (major > 5) return true
        //   if (major == 5) return patchLevel >= 10
        //   return false

        // 4.19-research-fork accept clause:
        if (major == 4 && patchLevel >= 19) return true

        // Original logic for everything else:
        if (major > 5) return true
        if (major == 5) return patchLevel >= 10
        return false
    }
}

fun parseKernelVersion(version: String): KernelVersion {
    val find = "(\\d+)\\.(\\d+)\\.(\\d+)".toRegex().find(version)
    return if (find != null) {
        KernelVersion(find.groupValues[1].toInt(), find.groupValues[2].toInt(), find.groupValues[3].toInt())
    } else {
        KernelVersion(-1, -1, -1)
    }
}

fun getKernelVersion(): KernelVersion {
    Os.uname().release.let {
        return parseKernelVersion(it)
    }
}