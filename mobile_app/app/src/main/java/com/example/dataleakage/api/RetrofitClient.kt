package com.example.dataleakage.api

import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

interface AnalysisApi {
    // 'suspend' keyword makes it work with your lifecycleScope.launch
    @POST("/analyze")
    suspend fun analyzeApp(@Body request: AnalysisRequest): AnalysisResponse
}

object RetrofitClient {
    private const val BASE_URL = "http://10.0.2.2:8000/"

    val api: AnalysisApi by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(AnalysisApi::class.java)
    }
}