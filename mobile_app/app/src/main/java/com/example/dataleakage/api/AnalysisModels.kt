package com.example.dataleakage.api

data class AnalysisRequest(
    val package_name: String,
    val permissions: List<String>
)

data class AnalysisResponse(
    val app: String,
    val risk_level: String,
    val score: Int,
    val leak_type: String,
    val pii_detected: List<String>,
    val sensitive_detected: List<String>,
    val detected_threats: List<String>
)
