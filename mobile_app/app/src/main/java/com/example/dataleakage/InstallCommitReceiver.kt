package com.example.dataleakage

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.widget.Toast

/**
 * Handles [PackageInstaller.Session.commit] callbacks. The system often sends
 * [PackageInstaller.STATUS_PENDING_USER_ACTION] first; we must [Context.startActivity]
 * on [Intent.EXTRA_INTENT] or the install UI never appears.
 */
class InstallCommitReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                if (confirm != null) {
                    try {
                        confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        context.startActivity(confirm)
                    } catch (e: Exception) {
                        Toast.makeText(
                            context.applicationContext,
                            e.message ?: "Could not open install screen",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }
            }
            PackageInstaller.STATUS_SUCCESS -> { }
            -999 -> { }
            else -> {
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                Toast.makeText(
                    context.applicationContext,
                    msg ?: "Install did not complete (status $status)",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }
}
