package com.example.dataleakage

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.dataleakage.api.AnalysisRequest
import com.example.dataleakage.api.RetrofitClient
import com.example.dataleakage.ui.SpeedometerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnScan = findViewById<Button>(R.id.btnScan)
        val container = findViewById<LinearLayout>(R.id.resultsContainer)
        val scanner = AppScanner(this)

        btnScan.setOnClickListener {

            container.removeAllViews()

            lifecycleScope.launch {

                val apps = withContext(Dispatchers.IO) {
                    scanner.getInstalledApps()
                        .filter {
                            scanner.getPermissions(it.packageName).isNotEmpty()
                        }
                        .take(5)
                }

                for (app in apps) {

                    val permissions =
                        scanner.getPermissions(app.packageName)

                    val request = AnalysisRequest(
                        app.packageName,
                        permissions
                    )

                    try {

                        val response =
                            RetrofitClient.api.analyzeApp(request)

                        addAppResult(
                            container,
                            response.app,
                            response.risk_level,
                            response.score,
                            response.pii_detected,
                            response.sensitive_detected
                        )

                    } catch (e: Exception) {
                        addError(container, app.packageName)
                    }
                }
            }
        }
    }

    private fun addAppResult(
        container: LinearLayout,
        appName: String,
        level: String,
        score: Int,
        pii: List<String>,
        sensitive: List<String>
    ) {

        val section = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 40, 0, 40)
        }

        val title = TextView(this).apply {
            text = "📦 $appName\nRisk: $level\nScore: $score/100"
            textSize = 16f
        }

        val speedometer = SpeedometerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                300
            )
            setScore(score)
        }

        val piiText = TextView(this).apply {
            text = "🔵 PII:\n${if (pii.isEmpty()) "None" else pii.joinToString("\n")}"
        }

        val sensitiveText = TextView(this).apply {
            text = "🟡 Sensitive:\n${if (sensitive.isEmpty()) "None" else sensitive.joinToString("\n")}"
        }

        section.addView(title)
        section.addView(speedometer)
        section.addView(piiText)
        section.addView(sensitiveText)

        container.addView(section)
    }

    private fun addError(container: LinearLayout, appName: String) {
        val errorText = TextView(this).apply {
            text = "❌ Failed to analyze: $appName\n"
        }
        container.addView(errorText)
    }
}