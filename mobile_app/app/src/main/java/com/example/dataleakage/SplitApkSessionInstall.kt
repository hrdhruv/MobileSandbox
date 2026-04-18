package com.example.dataleakage

import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.FileInputStream

/**
 * Same pipeline as `adb install-multiple`. Target package name is required on API 31+
 * for split sessions or the session may never show the install UI.
 *
 * Session artifact names must match each APK’s split identity from the manifest
 * (`split_<splitName>.apk` / `base.apk`), not temp names after staging from the picker.
 */
object SplitApkSessionInstall {

    private fun sessionEntryName(context: Context, apkFile: File): String {
        val pm = context.packageManager
        val pi = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(
                apkFile.absolutePath,
                PackageManager.PackageInfoFlags.of(0L)
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apkFile.absolutePath, 0)
        } ?: return apkFile.name

        val n = apkFile.name
        val splitNames = pi.splitNames
        return when {
            splitNames?.size == 1 -> {
                val split = splitNames[0]
                if (!split.isNullOrEmpty()) "split_$split.apk" else baseSessionName(n)
            }
            n.startsWith("split_", ignoreCase = true) && n.endsWith(".apk", ignoreCase = true) ->
                n
            else -> baseSessionName(n)
        }
    }

    private fun baseSessionName(fileName: String): String =
        if (fileName.endsWith(".apk", ignoreCase = true) &&
            fileName.startsWith("base", ignoreCase = true)
        ) {
            fileName
        } else {
            "base.apk"
        }

    private fun baseSortKey(sessionName: String): Int = when {
        sessionName.equals("base.apk", ignoreCase = true) -> 0
        sessionName.startsWith("base", ignoreCase = true) -> 1
        else -> 2
    }

    fun install(
        context: Context,
        apkFiles: List<File>,
        targetAppPackageName: String?,
        statusPendingIntent: PendingIntent
    ): Result<Unit> {
        if (apkFiles.isEmpty()) {
            return Result.failure(IllegalArgumentException("No APK files"))
        }
        val installer = context.packageManager.packageInstaller
        val totalBytes = apkFiles.sumOf { it.length() }
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                params.setSize(totalBytes)
            } catch (_: Exception) {
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val pkg = targetAppPackageName?.trim().orEmpty()
            if (pkg.isNotEmpty() && pkg != "unknown") {
                try {
                    params.setAppPackageName(pkg)
                } catch (_: Exception) {
                }
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            try {
                params.setPackageSource(PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE)
            } catch (_: Exception) {
            }
        }

        val sessionId = try {
            installer.createSession(params)
        } catch (e: Exception) {
            return Result.failure(e)
        }
        val session = installer.openSession(sessionId)
        return try {
            val entries = apkFiles
                .map { f -> f to sessionEntryName(context, f) }
                .sortedWith(
                    compareBy<Pair<File, String>> { baseSortKey(it.second) }
                        .thenBy { it.second }
                )
            val used = mutableSetOf<String>()
            for ((_, name) in entries) {
                if (!used.add(name)) {
                    session.abandon()
                    return Result.failure(
                        IllegalStateException("Duplicate APK slot \"$name\" — pick each split only once.")
                    )
                }
            }
            for ((file, name) in entries) {
                val len = file.length()
                session.openWrite(name, 0, len).use { out ->
                    FileInputStream(file).use { input -> input.copyTo(out) }
                }
            }
            session.commit(statusPendingIntent.intentSender)
            Result.success(Unit)
        } catch (e: Exception) {
            try {
                session.abandon()
            } catch (_: Exception) {
            }
            Result.failure(e)
        }
    }
}
