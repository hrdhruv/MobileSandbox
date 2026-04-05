package com.example.dataleakage

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.lifecycle.lifecycleScope
import com.example.dataleakage.api.AnalysisRequest
import com.example.dataleakage.api.FeedbackRequest
import com.example.dataleakage.api.RetrofitClient
import com.example.dataleakage.api.ScanRecord
import com.example.dataleakage.ui.SpeedometerView
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.imageview.ShapeableImageView
import com.google.android.material.snackbar.Snackbar
import com.airbnb.lottie.LottieAnimationView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    private val pickApkLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) processPickedApk(uri)
    }

    private lateinit var viewScan: ConstraintLayout
    private lateinit var viewHistory: ConstraintLayout
    private lateinit var container: LinearLayout
    private lateinit var lottieScan: LottieAnimationView
    private lateinit var btnScanFab: ShapeableImageView
    private lateinit var rvHistory: RecyclerView
    private lateinit var tvTotalScans: TextView
    private lateinit var emptyState: LinearLayout
    private lateinit var scanner: AppScanner

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        viewScan = findViewById(R.id.viewScan)
        viewHistory = findViewById(R.id.viewHistory)
        container = findViewById(R.id.resultsContainer)
        lottieScan = findViewById(R.id.lottieScan)
        btnScanFab = findViewById(R.id.btnScanFab)
        rvHistory = findViewById(R.id.rvHistory)
        tvTotalScans = findViewById(R.id.tvTotalScans)
        emptyState = findViewById(R.id.emptyState)
        val bottomNav = findViewById<BottomNavigationView>(R.id.bottomNavigationView)
        scanner = AppScanner(this)

        rvHistory.layoutManager = LinearLayoutManager(this)

        findViewById<com.google.android.material.button.MaterialButton>(R.id.btnPreInstallApk)
            .setOnClickListener {
                pickApkLauncher.launch(arrayOf("application/vnd.android.package-archive"))
            }

        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_scan -> {
                    viewScan.visibility = View.VISIBLE
                    viewHistory.visibility = View.GONE
                    true
                }
                R.id.nav_history -> {
                    viewScan.visibility = View.GONE
                    viewHistory.visibility = View.VISIBLE
                    loadHistory()
                    true
                }
                else -> false
            }
        }

        btnScanFab.setOnClickListener {
            container.removeAllViews()
            btnScanFab.isEnabled = false
            btnScanFab.alpha = 0.5f
            lottieScan.visibility = View.VISIBLE

            lifecycleScope.launch {
                // Do not skip apps with zero declared permissions — some installers
                // or edge cases return empty requestedPermissions; others still matter for inventory.
                val apps = withContext(Dispatchers.IO) {
                    scanner.getInstalledApps(includeSystemApps = false)
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
                            response.score, response.score_min, response.score_max, response.pii_detected,
                            response.sensitive_detected, permissions)
                    } catch (e: Exception) {
                        addError(container, app.packageName)
                    }
                }

                lottieScan.visibility = View.GONE
                btnScanFab.isEnabled = true
                btnScanFab.alpha = 1.0f
            }
        }
    }

    /**
     * Stock-Android "pre-install" path: APK is copied to app-private cache only,
     * permissions are read via [PackageManager.getPackageArchiveInfo], then the user
     * may open the system installer or delete the staged file.
     */
    private fun processPickedApk(uri: Uri) {
        lifecycleScope.launch {
            lottieScan.visibility = View.VISIBLE
            val staged = withContext(Dispatchers.IO) {
                ApkPreInstallStaging.stageApkFromUri(this@MainActivity, uri)
            }
            if (staged == null) {
                lottieScan.visibility = View.GONE
                Toast.makeText(
                    this@MainActivity,
                    "Could not read APK (try another file source).",
                    Toast.LENGTH_LONG
                ).show()
                return@launch
            }
            val pkgInfo = withContext(Dispatchers.IO) {
                ApkPreInstallStaging.readPackageInfo(this@MainActivity, staged)
            }
            if (pkgInfo == null) {
                ApkPreInstallStaging.deleteStaged(staged)
                lottieScan.visibility = View.GONE
                Toast.makeText(this@MainActivity, "Invalid or corrupt APK.", Toast.LENGTH_LONG).show()
                return@launch
            }
            val packageName = pkgInfo.packageName ?: "unknown"
            val permissions = ApkPreInstallStaging.permissionsList(pkgInfo)
            try {
                val response = withContext(Dispatchers.IO) {
                    RetrofitClient.api.analyzeApp(AnalysisRequest(packageName, permissions))
                }
                addPreInstallScanResult(
                    container, staged, packageName,
                    response.risk_level, response.score,
                    response.pii_detected, response.sensitive_detected, permissions
                )
            } catch (_: Exception) {
                ApkPreInstallStaging.deleteStaged(staged)
                addError(container, packageName)
            }
            lottieScan.visibility = View.GONE
        }
    }

    private fun loadHistory() {
        lifecycleScope.launch {
            try {
                val response = withContext(Dispatchers.IO) {
                    RetrofitClient.api.getScanHistory()
                }
                tvTotalScans.text = "Total Scans: ${response.scans.size}"
                if (response.scans.isEmpty()) {
                    emptyState.visibility = View.VISIBLE
                    rvHistory.visibility = View.GONE
                } else {
                    emptyState.visibility = View.GONE
                    rvHistory.visibility = View.VISIBLE
                    rvHistory.adapter = ScanHistoryAdapter(response.scans)
                    
                    // Add fade-in entrance animation
                    rvHistory.layoutAnimation = android.view.animation.LayoutAnimationController(
                        android.view.animation.AnimationUtils.loadAnimation(this@MainActivity, android.R.anim.fade_in)
                    )
                }
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity,
                    "Failed to load history: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun addAppResult(
        container: LinearLayout,
        appName: String,
        level: String,
        score: Int,
        scoreMin: Int,
        scoreMax: Int,
        pii: List<String>,
        sensitive: List<String>,
        permissions: List<String>
    ) {
        val cardView = MaterialCardView(this).apply {
            radius = 48f
            cardElevation = 18f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.setMargins(0, 0, 0, 48) }
        }

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        val levelColor = when (level) {
            "DANGEROUS"        -> Color.parseColor("#E74C3C")
            "SUSPICIOUS"       -> Color.parseColor("#E67E22")
            "HANDLE_WITH_CARE" -> Color.parseColor("#F39C12")
            else               -> Color.parseColor("#2ECC71")
        }

        val stripe = View(this).apply {
            setBackgroundColor(levelColor)
            layoutParams = LinearLayout.LayoutParams(12, LinearLayout.LayoutParams.MATCH_PARENT)
        }
        row.addView(stripe)

        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 36, 48, 36)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val displayLevel = level.replace("_", " ")

        val title = TextView(this).apply {
            text = appName
            setTextAppearance(android.R.style.TextAppearance_Material_Title) // TitleMedium equivalent or Material Components Title
            textSize = 20f
            setTextColor(Color.parseColor("#1A237E"))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        val badgeAndScore = LinearLayout(this).apply { 
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 16, 0, 16)
        }
        
        val riskBadge = TextView(this).apply {
            text = displayLevel
            textSize = 14f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setTextColor(levelColor)
            layoutParams = LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
            )
        }
        
        val scoreLabel = TextView(this).apply {
            text = "$scoreMin - $scoreMax / 100"
            textSize = 28f // large 28sp font
            setTextColor(levelColor)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        badgeAndScore.addView(riskBadge)
        badgeAndScore.addView(scoreLabel)

        val speedometer = SpeedometerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 280
            )
            setScore(score) // Internal expects 0-100 
        }

        val piiText = TextView(this).apply {
            text = "PII: ${if (pii.isEmpty()) "None" else pii.joinToString(", ")}"
            textSize = 12f
            setTextColor(Color.parseColor("#AAAAAA"))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).also { it.topMargin = 16 }
        }

        val sensitiveText = TextView(this).apply {
            text = "Sensitive: ${if (sensitive.isEmpty()) "None" else sensitive.joinToString(", ")}"
            textSize = 12f
            setTextColor(Color.parseColor("#AAAAAA"))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).also { it.topMargin = 8 }
        }

        val feedbackLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 32, 0, 0)
        }

        val btnMarkSafe = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply { 
            text = "Safe"
            setIconResource(android.R.drawable.ic_menu_preferences) // basic check mark
            iconTint = android.content.res.ColorStateList.valueOf(Color.parseColor("#2ECC71"))
        }
        
        val btnMarkMalware = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply { 
            text = "Malware"
            setIconResource(android.R.drawable.ic_dialog_alert)
            iconTint = android.content.res.ColorStateList.valueOf(Color.parseColor("#E74C3C"))
        }

        val submitFeedback: (Boolean) -> Unit = { isMalware ->
            btnMarkSafe.isEnabled = false
            btnMarkMalware.isEnabled = false
            btnMarkSafe.alpha = 0.4f
            btnMarkMalware.alpha = 0.4f
            sendFeedback(appName, permissions, isMalware, cardView)
        }
        btnMarkSafe.setOnClickListener { submitFeedback(false) }
        btnMarkMalware.setOnClickListener { submitFeedback(true) }

        feedbackLayout.addView(btnMarkSafe, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).also { it.rightMargin = 16 })
        feedbackLayout.addView(btnMarkMalware, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        inner.addView(title)
        inner.addView(badgeAndScore)
        inner.addView(speedometer)
        inner.addView(piiText)
        inner.addView(sensitiveText)
        inner.addView(feedbackLayout)
        
        row.addView(inner)
        cardView.addView(row)
        container.addView(cardView)
    }

    private fun addPreInstallScanResult(
        container: LinearLayout,
        stagedApk: File,
        packageName: String,
        level: String,
        score: Int,
        pii: List<String>,
        sensitive: List<String>,
        permissions: List<String>
    ) {
        val cardView = MaterialCardView(this).apply {
            radius = 48f
            cardElevation = 18f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.setMargins(0, 0, 0, 48) }
        }

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        val levelColor = when (level) {
            "DANGEROUS"        -> Color.parseColor("#E74C3C")
            "SUSPICIOUS"       -> Color.parseColor("#E67E22")
            "HANDLE_WITH_CARE" -> Color.parseColor("#F39C12")
            else               -> Color.parseColor("#2ECC71")
        }

        val stripe = View(this).apply {
            setBackgroundColor(levelColor)
            layoutParams = LinearLayout.LayoutParams(12, LinearLayout.LayoutParams.MATCH_PARENT)
        }
        row.addView(stripe)

        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 36, 48, 36)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val displayLevel = level.replace("_", " ")

        val title = TextView(this).apply {
            text = packageName
            setTextAppearance(android.R.style.TextAppearance_Material_Title)
            textSize = 20f
            setTextColor(Color.parseColor("#1A237E"))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        val sandboxHint = TextView(this).apply {
            text = "Pre-install scan — APK staged in app sandbox only (not installed)."
            textSize = 12f
            setTextColor(Color.parseColor("#5C6BC0"))
            setPadding(0, 8, 0, 0)
        }

        val badgeAndScore = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 16, 0, 16)
        }

        val riskBadge = TextView(this).apply {
            text = displayLevel
            textSize = 14f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setTextColor(levelColor)
            layoutParams = LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
            )
        }

        val scoreLabel = TextView(this).apply {
            text = "Risk: $score / 100"
            textSize = 28f
            setTextColor(levelColor)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        badgeAndScore.addView(riskBadge)
        badgeAndScore.addView(scoreLabel)

        val speedometer = SpeedometerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 280
            )
            setScore(score)
        }

        val piiText = TextView(this).apply {
            text = "PII: ${if (pii.isEmpty()) "None" else pii.joinToString(", ")}"
            textSize = 12f
            setTextColor(Color.parseColor("#AAAAAA"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.topMargin = 16 }
        }

        val sensitiveText = TextView(this).apply {
            text = "Sensitive: ${if (sensitive.isEmpty()) "None" else sensitive.joinToString(", ")}"
            textSize = 12f
            setTextColor(Color.parseColor("#AAAAAA"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.topMargin = 8 }
        }

        val decisionRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 32, 0, 0)
        }

        val btnInstall = MaterialButton(this).apply {
            text = "Install to device"
            setBackgroundColor(Color.parseColor("#2ECC71"))
        }
        val btnReject = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = "Reject & delete"
            setStrokeColor(android.content.res.ColorStateList.valueOf(Color.parseColor("#E74C3C")))
        }

        fun removeCard() {
            (cardView.parent as? ViewGroup)?.removeView(cardView)
        }

        btnInstall.setOnClickListener {
            try {
                val contentUri = FileProvider.getUriForFile(
                    this,
                    "${BuildConfig.APPLICATION_ID}.fileprovider",
                    stagedApk
                )
                val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                    data = contentUri
                    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                }
                startActivity(intent)
            } catch (e: Exception) {
                Toast.makeText(this, "Could not open installer: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }

        btnReject.setOnClickListener {
            ApkPreInstallStaging.deleteStaged(stagedApk)
            removeCard()
            Snackbar.make(container, "Staged APK removed.", Snackbar.LENGTH_SHORT).show()
        }

        decisionRow.addView(btnInstall, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
        ).also { it.rightMargin = 16 })
        decisionRow.addView(btnReject, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
        ))

        val feedbackLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 24, 0, 0)
        }

        val btnMarkSafe = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = "Mark safe"
            iconTint = android.content.res.ColorStateList.valueOf(Color.parseColor("#2ECC71"))
        }
        val btnMarkMalware = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = "Mark malware"
            iconTint = android.content.res.ColorStateList.valueOf(Color.parseColor("#E74C3C"))
        }

        val submitFeedback: (Boolean) -> Unit = { isMalware ->
            btnMarkSafe.isEnabled = false
            btnMarkMalware.isEnabled = false
            btnMarkSafe.alpha = 0.4f
            btnMarkMalware.alpha = 0.4f
            sendFeedback(packageName, permissions, isMalware, cardView)
        }
        btnMarkSafe.setOnClickListener { submitFeedback(false) }
        btnMarkMalware.setOnClickListener { submitFeedback(true) }

        feedbackLayout.addView(btnMarkSafe, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
        ).also { it.rightMargin = 16 })
        feedbackLayout.addView(btnMarkMalware, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
        ))

        inner.addView(title)
        inner.addView(sandboxHint)
        inner.addView(badgeAndScore)
        inner.addView(speedometer)
        inner.addView(piiText)
        inner.addView(sensitiveText)
        inner.addView(decisionRow)
        inner.addView(feedbackLayout)

        row.addView(inner)
        cardView.addView(row)
        container.addView(cardView, 0)
    }

    private fun sendFeedback(packageName: String, permissions: List<String>, isMalware: Boolean, view: View) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    RetrofitClient.api.sendFeedback(FeedbackRequest(packageName, permissions, isMalware))
                }
                Snackbar.make(view, "Feedback recorded. Thank you.", Snackbar.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Snackbar.make(view, "Failed to submit feedback", Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    private fun addError(container: LinearLayout, appName: String) {
        container.addView(TextView(this).apply {
            text = "❌ Failed to analyze: $appName"
            setPadding(0, 8, 0, 8)
            setTextColor(Color.WHITE)
        })
    }
}