package com.example.dataleakage

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnScan = findViewById<Button>(R.id.btnScan)
        val txtResults = findViewById<TextView>(R.id.txtResults)

        val scanner = AppScanner(this)

        btnScan.setOnClickListener {
            txtResults.text = "Scanning installed apps...\n\n"

            lifecycleScope.launch {
                try {
                    val apps = scanner.getInstalledApps()
                    val report = StringBuilder()

                    for (app in apps.take(5)) { // limit for demo
                        val permissions = scanner.getPermissions(app.packageName)

                        report.append("App: ${app.packageName}\n")
                        report.append("Permissions (${permissions.size}):\n")

                        for (perm in permissions) {
                            report.append(" - $perm\n")
                        }
                        report.append("\n----------------------\n\n")
                    }

                    txtResults.text = report.toString()

                } catch (e: Exception) {
                    txtResults.text = "Error during scan:\n${e.message}"
                }
            }
        }
    }
}
