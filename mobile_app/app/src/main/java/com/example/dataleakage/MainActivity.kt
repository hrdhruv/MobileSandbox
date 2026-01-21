package com.example.dataleakage

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.dataleakage.api.AnalysisRequest
import com.example.dataleakage.api.RetrofitClient
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Make sure IDs match your XML (btnScan vs btn_scan)
        val btnScan = findViewById<Button>(R.id.btnScan) 
        val txtResults = findViewById<TextView>(R.id.txtResults)

        val scanner = AppScanner(this)

        btnScan.setOnClickListener {
            txtResults.text = "Connecting to Analysis Engine...\n"

            // Using Coroutines (Your existing style)
            lifecycleScope.launch {
                try {
                    val apps = scanner.getInstalledApps()
                    
                    // Filter: Only check apps that actually requested permissions
                    val appsWithPerms = apps.filter { 
                        scanner.getPermissions(it.packageName).isNotEmpty() 
                    }

                    txtResults.append("Found ${appsWithPerms.size} apps. Scanning top 5...\n\n")

                    // Take 5 for demo
                    for (app in appsWithPerms.take(5)) {
                        val pkgName = app.packageName
                        val permissions = scanner.getPermissions(pkgName)

                        // 1. Prepare Request
                        val request = AnalysisRequest(pkgName, permissions)
                        
                        try {
                            // 2. CALL PYTHON (This waits here until Python replies)
                            val response = RetrofitClient.api.analyzeApp(request)

                            // 3. SHOW RESULT
                            val output = """
                                📦 App: ${response.app}
                                🛡️ Risk: ${response.risk_level} (Score: ${response.score})
                                🚩 Flags: ${response.detected_threats}
                                ----------------------
                            """.trimIndent()
                            
                            txtResults.append("$output\n\n")

                        } catch (e: Exception) {
                            txtResults.append("❌ Failed to analyze $pkgName: ${e.message}\n")
                        }
                    }

                } catch (e: Exception) {
                    txtResults.text = "Error during scan: ${e.message}"
                }
            }
        }
    }
}