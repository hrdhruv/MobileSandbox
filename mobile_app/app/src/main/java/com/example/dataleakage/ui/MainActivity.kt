package com.example.datalakeage

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

interface AnalysisApi {
    @POST("/analyze")
    suspend fun analyzeApp(@Body request: ScanRequest): ScanResponse
}

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Simple UI Layout created programmatically for the demo
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 50, 50, 50)
        }
        val btnScan = Button(this).apply { text = "Start Security Scan" }
        val txtResults = TextView(this).apply { text = "Results will appear here..." }
        layout.addView(btnScan)
        layout.addView(txtResults)
        setContentView(layout)

        val scanner = AppScanner(this)

        // IMPORTANT: Use 10.0.2.2 if using Android Emulator, or your Laptop IP if using a real phone
        val retrofit = Retrofit.Builder()
            .baseUrl("http://10.0.2.2:8000") 
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        val api = retrofit.create(AnalysisApi::class.java)

        btnScan.setOnClickListener {
            txtResults.text = "Scanning Apps and sending to Sandbox..."
            lifecycleScope.launch {
                try {
                    val apps = scanner.getInstalledApps().take(3) // Scan first 3 for demo
                    var report = "--- SCAN REPORT ---\n\n"
                    
                    for (app in apps) {
                        val perms = scanner.getPermissions(app.packageName)
                        val response = api.analyzeApp(ScanRequest(app.packageName, perms))
                        report += "Package: ${response.app}\nRisk: ${response.risk_level}\nThreats: ${response.detected_threats}\n\n"
                    }
                    txtResults.text = report
                } catch (e: Exception) {
                    txtResults.text = "Connection Error: Ensure Python server is running!\n${e.message}"
                }
            }
        }
    }
}