package com.example.dataleakage

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

class AppScanner(private val context: Context) {

    fun getInstalledApps(): List<ApplicationInfo> {
        return context.packageManager
            .getInstalledApplications(PackageManager.GET_META_DATA)
            .filter {
                (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0
            }
    }

    fun getPermissions(packageName: String): List<String> {
        return try {
            val info = context.packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS
            )
            info.requestedPermissions?.toList() ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
