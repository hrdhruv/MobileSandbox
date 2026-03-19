package com.example.dataleakage.api

data class AnalysisRequest(
    val package_name: String,
    val permissions: List<String>
)

data class AnalysisResponse(
    val app: String,
    val risk_level: String,
    val score: Int,
    val score_precise: Double = 0.0,
    val leak_type: String,
    val pii_detected: List<String>,
    val sensitive_detected: List<String>,
    val detected_threats: List<String>
)

data class FeedbackRequest(
    val package_name: String,
    val permissions: List<String>,
    val is_malware: Boolean,
    val user_notes: String = ""
)

data class FeedbackResponse(
    val status: String,
    val `package`: String = "",
    val is_malware: Boolean = false
)

data class ScanRecord(
    val id: Int = 0,
    val package_name: String,
    val risk_level: String,
    val score: Double,
    val leak_type: String?,
    val pii_detected: String?,
    val sensitive_detected: String?,
    val detected_threats: String?,
    val timestamp: String?
)

data class ScanHistoryResponse(
    val scans: List<ScanRecord>
)
