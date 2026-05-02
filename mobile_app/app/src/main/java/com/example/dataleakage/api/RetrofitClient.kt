package com.example.dataleakage.api

import com.example.dataleakage.BuildConfig
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

interface AnalysisApi {
    @POST("/analyze")
    suspend fun analyzeApp(@Body request: AnalysisRequest): AnalysisResponsei

    @POST("/feedback")
    suspend fun sendFeedback(@Body request: FeedbackRequest): FeedbackResponse

    @GET("/scan/history")
    suspend fun getScanHistory(): ScanHistoryResponse
}

object RetrofitClient {
    private val baseUrl: String = BuildConfig.ANALYSIS_API_BASE_URL

    val api: AnalysisApi by lazy {
        Retrofit.Builder()
            .baseUrl(baseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(AnalysisApi::class.java)
    }
}