package com.example.dataleakage

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

class AppScanner(private val context: Context) {

    /**
     * @param includeSystemApps If true, includes system/updated apps (typical
     *   sandbox-style full inventory). If false, only non-system user apps.
     */
    fun getInstalledApps(includeSystemApps: Boolean = false): List<ApplicationInfo> {
        val all = context.packageManager
            .getInstalledApplications(PackageManager.GET_META_DATA)
        return if (includeSystemApps) {
            all
        } else {
            all.filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
        }
    }

    fun getPermissions(packageName: String): List<String> {
        return try {
            val pm = context.packageManager
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(
                        PackageManager.GET_PERMISSIONS.toLong()
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }
            info.requestedPermissions?.toList() ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
