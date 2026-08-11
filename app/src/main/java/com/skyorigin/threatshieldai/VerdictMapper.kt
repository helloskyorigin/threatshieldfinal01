package com.skyorigin.threatshieldai

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.PriorityHigh
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector

data class VerdictInfo(
    val titleEn: String,
    val titleHi: String = "",
    val color: Color,
    val colorInt: Int,
    val subtitleEn: String,
    val subtitleHi: String = "",
    val icon: ImageVector
) {
    fun getTitle(isHindi: Boolean = false): String = titleEn
    fun getSubtitle(isHindi: Boolean = false): String = subtitleEn
}

object VerdictMapper {
    fun getVerdictForScore(score: Int): VerdictInfo {
        return when (score.coerceIn(0, 100)) {
            in 0..39 -> VerdictInfo(
                titleEn = "SAFE",
                titleHi = "SAFE",
                color = Color(0xFF22C55E), // Green
                colorInt = 0xFF22C55E.toInt(),
                subtitleEn = "Safe message pattern detected.",
                subtitleHi = "Safe message pattern detected.",
                icon = Icons.Rounded.Check
            )
            in 40..69 -> VerdictInfo(
                titleEn = "SUSPICIOUS",
                titleHi = "SUSPICIOUS",
                color = Color(0xFFF59E0B), // Amber / Orange
                colorInt = 0xFFF59E0B.toInt(),
                subtitleEn = "Suspicious activity indicators detected.",
                subtitleHi = "Suspicious activity indicators detected.",
                icon = Icons.Rounded.Warning
            )
            else -> VerdictInfo( // 70..100
                titleEn = "DANGER",
                titleHi = "DANGER",
                color = Color(0xFFEF4444), // Red
                colorInt = 0xFFEF4444.toInt(),
                subtitleEn = "High-risk scam indicators detected.",
                subtitleHi = "High-risk scam indicators detected.",
                icon = Icons.Rounded.PriorityHigh
            )
        }
    }
}
