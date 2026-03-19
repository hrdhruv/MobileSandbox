package com.example.dataleakage.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View
import android.view.animation.DecelerateInterpolator
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

class SpeedometerView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private var score: Float = 0f
    private var animatedScore: Float = 0f

    private val arcPaint = Paint().apply {
        style = Paint.Style.STROKE
        strokeWidth = 40f
        strokeCap = Paint.Cap.ROUND
        isAntiAlias = true
    }

    private val needlePaint = Paint().apply {
        color = Color.BLACK
        strokeWidth = 10f
        isAntiAlias = true
    }

    private val textPaint = Paint().apply {
        color = Color.BLACK
        textSize = 70f
        textAlign = Paint.Align.CENTER
        isAntiAlias = true
        typeface = Typeface.DEFAULT_BOLD
    }

    fun setScore(value: Int) {
        score = value.coerceIn(0, 100).toFloat()

        val animator = ValueAnimator.ofFloat(animatedScore, score)
        animator.duration = 800
        animator.interpolator = DecelerateInterpolator()

        animator.addUpdateListener {
            animatedScore = it.animatedValue as Float
            invalidate()
        }

        animator.start()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val w = width.toFloat()
        val h = height.toFloat()

        val radius = min(w, h) / 2 - 60
        val centerX = w / 2
        val centerY = h * 0.85f

        val rect = RectF(
            centerX - radius,
            centerY - radius,
            centerX + radius,
            centerY + radius
        )

        // 4-segment arc: GREEN (0-30) → ORANGE (30-50) → YELLOW (50-70) → RED (70-100)
        // Total sweep = 180°. Each unit = 1.8°.

        // GREEN ARC (0–30): 30 units × 1.8° = 54°
        arcPaint.color = Color.parseColor("#4CAF50")
        canvas.drawArc(rect, 180f, 54f, false, arcPaint)

        // ORANGE ARC (30–50): 20 units × 1.8° = 36°  — HANDLE WITH CARE
        arcPaint.color = Color.parseColor("#FF9800")
        canvas.drawArc(rect, 234f, 36f, false, arcPaint)

        // YELLOW ARC (50–70): 20 units × 1.8° = 36°
        arcPaint.color = Color.parseColor("#FFC107")
        canvas.drawArc(rect, 270f, 36f, false, arcPaint)

        // RED ARC (70–100): 30 units × 1.8° = 54°
        arcPaint.color = Color.parseColor("#F44336")
        canvas.drawArc(rect, 306f, 54f, false, arcPaint)

        // Needle angle (maps 0–100 score to 180°–360° sweep)
        val angle = 180 + (animatedScore * 1.8f)
        val rad = Math.toRadians(angle.toDouble())

        val needleX = (centerX + radius * cos(rad)).toFloat()
        val needleY = (centerY + radius * sin(rad)).toFloat()

        canvas.drawLine(centerX, centerY, needleX, needleY, needlePaint)

        // Center dot
        canvas.drawCircle(centerX, centerY, 14f, needlePaint)

        // Score text above arc
        canvas.drawText(
            animatedScore.toInt().toString(),
            centerX,
            centerY - radius - 30,
            textPaint
        )
    }
}