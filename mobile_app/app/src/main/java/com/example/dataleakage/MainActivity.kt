package com.example.dataleakage

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.lifecycle.lifecycleScope
import com.example.dataleakage.api.AnalysisRequest
import com.example.dataleakage.api.FeedbackRequest
import com.example.dataleakage.api.RetrofitClient
import com.example.dataleakage.ui.SpeedometerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnScan    = findViewById<Button>(R.id.btnScan)
        val btnHistory = findViewById<Button>(R.id.btnHistory)
        val container  = findViewById<LinearLayout>(R.id.resultsContainer)
        val progress   = findViewById<ProgressBar>(R.id.scanProgress)
        val scanner    = AppScanner(this)

        // ── Navigate to Scan History ──
        btnHistory.setOnClickListener {
            startActivity(android.content.Intent(this, ScanHistoryActivity::class.java))
        }

        // ── Scan apps ──
        btnScan.setOnClickListener {
            container.removeAllViews()
            btnScan.isEnabled = false
            progress.visibility = View.VISIBLE

            lifecycleScope.launch {
                val apps = withContext(Dispatchers.IO) {
                    scanner.getInstalledApps()
                        .filter { scanner.getPermissions(it.packageName).isNotEmpty() }
                        .take(5)
                }

                for (app in apps) {
                    val permissions = scanner.getPermissions(app.packageName)
                    try {
                        val response = withContext(Dispatchers.IO) {
                            RetrofitClient.api.analyzeApp(
                                AnalysisRequest(app.packageName, permissions)
                            )
                        }
                        addAppResult(container, response.app, response.risk_level,
                            response.score, response.pii_detected,
                            response.sensitive_detected, permissions)
                    } catch (e: Exception) {
                        addError(container, app.packageName)
                    }
                }

                progress.visibility = View.GONE
                btnScan.isEnabled = true
            }
        }
    }

    // ─────────────────────────────────────────
    //  Render one app result card
    // ─────────────────────────────────────────

    private fun addAppResult(
        container: LinearLayout,
        appName: String,
        level: String,
        score: Int,
        pii: List<String>,
        sensitive: List<String>,
        permissions: List<String>
    ) {
        // ── CardView wrapper ──
        val cardView = CardView(this).apply {
            radius = 12f
            cardElevation = 8f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.setMargins(0, 0, 0, 20) }
        }

        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 24, 28, 24)
        }

        // ── Risk level → color + emoji ──
        val (emoji, levelColor, displayLevel) = when (level) {
            "DANGEROUS"        -> Triple("🔴", Color.parseColor("#D32F2F"), "DANGEROUS")
            "SUSPICIOUS"       -> Triple("🟡", Color.parseColor("#F57F17"), "SUSPICIOUS")
            "HANDLE_WITH_CARE" -> Triple("🟠", Color.parseColor("#E65100"), "HANDLE WITH CARE")
            else               -> Triple("🟢", Color.parseColor("#2E7D32"), "SAFE")
        }

        val title = TextView(this).apply {
            text = "📦 $appName"
            textSize = 15f
            setTextColor(Color.parseColor("#1A237E"))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        val riskBadge = TextView(this).apply {
            text = "$emoji  $displayLevel"
            textSize = 13f
            setTextColor(Color.WHITE)
            setBackgroundColor(levelColor)
            setPadding(16, 8, 16, 8)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.topMargin = 6 }
        }

        val scoreLabel = TextView(this).apply {
            text = "Risk Score: $score / 100"
            textSize = 13f
            setTextColor(levelColor)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.topMargin = 4 }
        }

        val speedometer = SpeedometerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 280
            )
            setScore(score)
        }

        val piiText = TextView(this).apply {
            text = "🔵 PII: ${if (pii.isEmpty()) "None" else pii.joinToString(", ")}"
            textSize = 12f
            setTextColor(Color.parseColor("#444444"))
        }

        val sensitiveText = TextView(this).apply {
            text = "🟡 Sensitive: ${if (sensitive.isEmpty()) "None" else sensitive.joinToString(", ")}"
            textSize = 12f
            setTextColor(Color.parseColor("#444444"))
        }

        // ── Feedback buttons (standard Button — no Material3 dependency) ──
        val feedbackLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 12, 0, 0)
        }

        val btnMarkSafe    = Button(this).apply { text = "✅ Mark Safe" }
        val btnMarkMalware = Button(this).apply { text = "⚠️ Mark Malware" }

        // Disable both after first tap to prevent double-submit
        val submitFeedback: (Boolean) -> Unit = { isMalware ->
            btnMarkSafe.isEnabled    = false
            btnMarkMalware.isEnabled = false
            sendFeedback(appName, permissions, isMalware)
        }
        btnMarkSafe.setOnClickListener    { submitFeedback(false) }
        btnMarkMalware.setOnClickListener { submitFeedback(true)  }

        feedbackLayout.addView(btnMarkSafe, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        feedbackLayout.addView(btnMarkMalware, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        inner.addView(title)
        inner.addView(riskBadge)
        inner.addView(scoreLabel)
        inner.addView(speedometer)
        inner.addView(piiText)
        inner.addView(sensitiveText)
        inner.addView(feedbackLayout)
        cardView.addView(inner)
        container.addView(cardView)
    }

    // ─────────────────────────────────────────
    //  Send feedback to server
    // ─────────────────────────────────────────

    private fun sendFeedback(packageName: String, permissions: List<String>,
                             isMalware: Boolean) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    RetrofitClient.api.sendFeedback(
                        FeedbackRequest(packageName, permissions, isMalware)
                    )
                }
                Toast.makeText(this@MainActivity,
                    "Feedback submitted for $packageName", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity,
                    "Failed to submit feedback", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun addError(container: LinearLayout, appName: String) {
        container.addView(TextView(this).apply {
            text = "❌ Failed to analyze: $appName"
            setPadding(0, 8, 0, 8)
        })
    }
}