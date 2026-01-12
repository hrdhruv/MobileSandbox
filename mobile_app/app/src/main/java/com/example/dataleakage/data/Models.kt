package com.example.dataleakage

data class ScanRequest(val package_name: String, val permissions: List<String>)
data class ScanResponse(
    val app: String,
    val risk_level: String,
    val score: Int,
    val detected_threats: List<String>
)