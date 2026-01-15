package com.example.dataleakage

interface AnalysisApi {
    @POST("/analyze")
    suspend fun getAnalysis(@Body request: ScanRequest): AnalysisResponse
}

data class ScanRequest(val package_name: String, val permissions: List<String>)
data class AnalysisResponse(val risk_level: String, val score: Int, val flags: List<String>)