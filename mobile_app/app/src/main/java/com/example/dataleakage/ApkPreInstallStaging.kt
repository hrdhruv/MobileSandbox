package com.example.dataleakage

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import java.io.File

/**
 * Stages picked APK(s) in app-private cache and reads [PackageInfo] without installing.
 * Original files live where the user picked them (e.g. Downloads); deleting the sandbox
 * copy does not remove those unless we delete via the returned content [Uri]s.
 */
object ApkPreInstallStaging {

    data class SourceDeletionResult(val deletedCount: Int, val failedCount: Int)

    fun stagingDir(context: Context): File =
        File(context.cacheDir, "preinstall_sandbox").apply { mkdirs() }

    /**
     * Keep read/write access after the picker closes so "Reject" can delete Documents/Downloads rows.
     */
    fun takePersistableReadWrite(context: Context, uris: List<Uri>) {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        for (uri in uris) {
            try {
                context.contentResolver.takePersistableUriPermission(uri, flags)
            } catch (_: SecurityException) {
            }
        }
    }

    fun displayName(context: Context, uri: Uri): String? {
        context.contentResolver.query(
            uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null
        )?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (i >= 0) return c.getString(i)
            }
        }
        return null
    }

    /** Best-effort real `.apk` filename for staging (picker display name, else URI segment). */
    fun preferredApkFilename(context: Context, uri: Uri, idx: Int): String {
        displayName(context, uri)
            ?.takeIf { it.endsWith(".apk", ignoreCase = true) }
            ?.let { return it }
        val seg = uri.lastPathSegment ?: return "staged_${System.currentTimeMillis()}_$idx.apk"
        val decoded = Uri.decode(seg).substringAfterLast('/')
        return if (decoded.endsWith(".apk", ignoreCase = true)) decoded
        else "staged_${System.currentTimeMillis()}_$idx.apk"
    }

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

    fun stageApksFromUris(context: Context, uris: List<Uri>): List<File> {
        val dir = stagingDir(context)
        val out = mutableListOf<File>()
        var idx = 0
        for (uri in uris) {
            val rawName = preferredApkFilename(context, uri, idx)
            idx++
            val safeName = rawName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
            var dest = File(dir, safeName)
            var n = 0
            while (dest.exists()) {
                dest = File(dir, "${safeName.substringBeforeLast(".")}_$n.apk")
                n++
            }
            try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    dest.outputStream().use { output -> input.copyTo(output) }
                } ?: continue
                out.add(dest)
            } catch (_: Exception) {
                dest.delete()
            }
        }
        return out
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

    fun findBaseApk(files: List<File>): File? =
        files.find { it.name.equals("base.apk", ignoreCase = true) }
            ?: files.find { it.name.startsWith("base", ignoreCase = true) }
            ?: files.firstOrNull()

    fun readPackageInfoFromSplitSet(context: Context, files: List<File>): PackageInfo? {
        val ordered = mutableListOf<File>()
        findBaseApk(files)?.let { ordered.add(it) }
        files.filter { it !in ordered }.sortedBy { it.name }.forEach { ordered.add(it) }
        for (f in ordered) {
            readPackageInfo(context, f)?.let { return it }
        }
        return null
    }

    fun permissionsList(info: PackageInfo): List<String> =
        info.requestedPermissions?.toList() ?: emptyList()

    fun deleteStaged(apkFile: File?) {
        try {
            apkFile?.delete()
        } catch (_: Exception) { }
    }

    fun deleteStagedList(files: List<File>?) {
        files?.forEach { deleteStaged(it) }
    }

    /**
     * Remove the user's original file(s) (e.g. in Downloads) when we still hold URI permission.
     */
    fun tryDeleteSourceUris(context: Context, uris: List<Uri>): SourceDeletionResult {
        var deleted = 0
        var failed = 0
        for (uri in uris) {
            val ok = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    DocumentsContract.deleteDocument(context.contentResolver, uri)
                } else {
                    @Suppress("DEPRECATION")
                    context.contentResolver.delete(uri, null, null) > 0
                }
            } catch (_: Exception) {
                try {
                    context.contentResolver.delete(uri, null, null) > 0
                } catch (_: Exception) {
                    false
                }
            }
            if (ok) deleted++ else failed++
        }
        return SourceDeletionResult(deleted, failed)
    }
}
