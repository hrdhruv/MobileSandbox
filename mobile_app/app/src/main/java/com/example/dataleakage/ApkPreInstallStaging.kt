package com.example.dataleakage

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import java.io.File

/**
 * Stages a picked APK in app-private cache ("sandbox" storage) and reads
 * [PackageInfo] without installing — closest stock-Android equivalent to
 * pre-install analysis.
 */
object ApkPreInstallStaging {

    fun stagingDir(context: Context): File =
        File(context.cacheDir, "preinstall_sandbox").apply { mkdirs() }

    /**
     * Copy content [uri] into cache and return the file, or null on failure.
     */
    fun stageApkFromUri(context: Context, uri: Uri): File? {
        return try {
            val dir = stagingDir(context)
            val out = File(dir, "staged_${System.currentTimeMillis()}.apk")
            context.contentResolver.openInputStream(uri)?.use { input ->
                out.outputStream().use { output -> input.copyTo(output) }
            } ?: return null
            out
        } catch (_: Exception) {
            null
        }
    }

    fun readPackageInfo(context: Context, apkFile: File): PackageInfo? {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(
                apkFile.absolutePath,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.GET_PERMISSIONS)
        }
    }

    fun permissionsList(info: PackageInfo): List<String> =
        info.requestedPermissions?.toList() ?: emptyList()

    fun deleteStaged(apkFile: File?) {
        try {
            apkFile?.delete()
        } catch (_: Exception) { }
    }
}
