package com.skyorigin.threatshieldai

data class MessageAnalysis(
    val text: String,
    val date: String,
    val status: String,
    val score: Int,
    val summary: String = "",
    val reasons: List<String> = emptyList(),
    val links: List<String> = emptyList(),
    val explain15: String = "",
    val timestamp: Long = System.currentTimeMillis(),
    val scamType: String = "",
    val urlStatuses: List<String> = emptyList(),
    val advice: List<String> = emptyList(),
    val confidence: Int = 0,
    val signals: List<String> = emptyList()
)

// Extension functions for multi-lingual and formatting support across screens

fun MessageAnalysis.getTextVerdict(): String {
    val info = VerdictMapper.getVerdictForScore(score)
    return when (info.titleEn) {
        "DANGER", "HIGH RISK" -> "Danger"
        "SUSPICIOUS" -> "Suspicious"
        else -> "Safe"
    }
}

fun MessageAnalysis.getUrlVerdict(): String {
    if (links.isEmpty()) return "Safe"
    val metadata = urlStatuses.firstOrNull { it.startsWith("METADATA:") }
    if (metadata != null) {
        try {
            val json = org.json.JSONObject(metadata.substring("METADATA:".length))
            val v = json.optString("url_verdict", "Safe")
            if (v.equals("MALICIOUS", ignoreCase = true) || v.equals("Danger", ignoreCase = true)) {
                return "Danger"
            }
            return v
        } catch (e: Exception) {}
    }
    var hasDanger = false
    var hasUnknown = false
    var hasSuspicious = false
    urlStatuses.forEach { statusStr ->
        if (!statusStr.startsWith("METADATA:")) {
            try {
                val json = org.json.JSONObject(statusStr)
                val risk = json.optString("risk_level", "safe").lowercase()
                if (risk == "danger" || risk == "malicious") hasDanger = true
                if (risk == "unknown" || risk == "failed" || risk == "unverified") hasUnknown = true
                if (risk == "suspicious") hasSuspicious = true
            } catch (e: Exception) {}
        }
    }
    return when {
        hasDanger -> "Danger"
        hasUnknown -> "Unknown"
        hasSuspicious -> "Suspicious"
        else -> "Safe"
    }
}

fun MessageAnalysis.getLocalizedStatus(isHindi: Boolean): String {
    return VerdictMapper.getVerdictForScore(score).titleEn
}

fun MessageAnalysis.getRiskLevelLabel(isHindi: Boolean): String {
    return VerdictMapper.getVerdictForScore(score).titleEn
}

fun MessageAnalysis.getConfidenceLabel(isHindi: Boolean): String {
    val conf = if (confidence > 0) confidence else 50
    return when {
        conf >= 80 -> "High (${conf}%)"
        conf >= 50 -> "Medium (${conf}%)"
        else -> "Low (${conf}%)"
    }
}

fun MessageAnalysis.getLocalizedSummary(isHindi: Boolean): String {
    if (summary.isNotEmpty() && 
        !summary.contains("temporarily unavailable") && 
        !summary.contains("अस्थायी रूप से अनुपलब्ध")) {
        return summary
    }
    val st = status.lowercase()
    return when {
        st.contains("danger") || st.contains("unsafe") || score >= 70 -> {
            "This message shows clear signs of a security threat or scam."
        }
        st.contains("suspicious") || score >= 40 -> {
            "This message has some suspicious patterns. Proceed with caution."
        }
        else -> {
            "This message appears safe with no threat indicators detected."
        }
    }
}

fun MessageAnalysis.getLocalizedExplain15(isHindi: Boolean): String {
    if (explain15.isNotEmpty() && 
        !explain15.contains("temporarily unavailable") && 
        !explain15.contains("अस्थायी रूप से अनुपलब्ध")) {
        return explain15
    }
    val st = status.lowercase()
    return when {
        st.contains("danger") || st.contains("unsafe") || score >= 70 -> {
            "High-risk threat detected: message exhibits severe deceptive impersonation, credential harvesting, or payment trap indicators."
        }
        st.contains("suspicious") || score >= 40 -> {
            "Security analysis detected suspicious urgency cues and unverified external elements. Exercise caution before responding."
        }
        else -> {
            "Security analysis verified message integrity with no phishing links or deceptive indicators detected."
        }
    }
}

fun MessageAnalysis.getMappedSignals(isHindi: Boolean): List<String> {
    if (signals.isNotEmpty()) return signals
    return reasons
}

fun MessageAnalysis.getLocalAdvice(isHindi: Boolean): List<String> {
    if (advice.isNotEmpty()) return advice

    val textLower = text.lowercase()
    val isDanger = status.lowercase() in listOf("danger", "unsafe")
    val isWarning = status.lowercase() == "warning"
    val isSuspicious = status.lowercase() == "suspicious"
    val isSafe = !isDanger && !isWarning && !isSuspicious
    val hasLink = links.isNotEmpty()

    val urlVerdict = getUrlVerdict()
    val isKnownThreatUrl = urlVerdict == "Danger"
    val isUnverifiedUrl = urlVerdict == "Unknown" || urlVerdict == "Suspicious"

    val asksForOtp = textLower.contains("otp") || textLower.contains("pin") || textLower.contains("password") || textLower.contains("passcode") || textLower.contains("cvv") || textLower.contains("one-time") || textLower.contains("one time")
    val asksForVerification = textLower.contains("verify") || textLower.contains("verification") || textLower.contains("kyc") || textLower.contains("update") || textLower.contains("satyapan") || textLower.contains("सत्यापन")
    val isUrgent = textLower.contains("urgent") || textLower.contains("urgency") || textLower.contains("immediately") || textLower.contains("now") || textLower.contains("today") || textLower.contains("expire") || textLower.contains("suspend") || textLower.contains("blocked")
    val isPrizeOrRefund = textLower.contains("won") || textLower.contains("prize") || textLower.contains("reward") || textLower.contains("cash") || textLower.contains("lottery") || textLower.contains("refund") || textLower.contains("claim") || textLower.contains("crore") || textLower.contains("lakh") || textLower.contains("gpay") || textLower.contains("paytm") || textLower.contains("phonepe") || textLower.contains("gift")
    val isBankOrUpi = textLower.contains("bank") || textLower.contains("upi") || textLower.contains("sbi") || textLower.contains("hdfc") || textLower.contains("icici") || textLower.contains("card") || textLower.contains("account")

    val scamTypeLower = scamType.lowercase()
    val isPhishingScam = scamTypeLower.contains("phish") || scamTypeLower.contains("social engineering")
    val isOtpScam = scamTypeLower.contains("otp") || scamTypeLower.contains("pin") || scamTypeLower.contains("credential") || asksForOtp
    val isRefundScam = scamTypeLower.contains("refund")
    val isBankScam = scamTypeLower.contains("bank") || scamTypeLower.contains("upi") || scamTypeLower.contains("financial")
    val isPrizeScam = scamTypeLower.contains("prize") || scamTypeLower.contains("lottery") || scamTypeLower.contains("reward") || scamTypeLower.contains("gift")

    val actions = mutableListOf<String>()

    if (isDanger) {
        if (isKnownThreatUrl) {
            actions.add("Do not open the detected Link; it is a confirmed threat.")
            actions.add("Do not enter personal, financial, login, OTP, or other sensitive information.")
            actions.add("Verify the sender through an official channel if necessary.")
            actions.add("Block/report the sender when appropriate.")
        } else {
            if (hasLink) {
                actions.add("Do not tap on the suspicious Link in this message.")
            }
            
            if (asksForOtp) {
                actions.add("Never share OTP, PIN, or passwords with anyone.")
            }
            
            if (isBankOrUpi || isRefundScam || isBankScam) {
                actions.add("Keep your banking details secure and do not transfer money to unknown accounts.")
            } else if (isPrizeScam || isPrizeOrRefund) {
                actions.add("Ignore claims of unexpected lottery, cashback, or rewards.")
            }
            
            if (asksForVerification || isUrgent) {
                actions.add("Do not perform verification or account updates under urgency pressure.")
            }
            
            // Fallbacks to reach at least 2 actions
            if (actions.size < 2) {
                actions.add("Block and report this sender immediately.")
            }
            if (actions.size < 2) {
                actions.add("Avoid interacting with similar messages for future safety.")
            }
        }
        
        return actions.distinct().take(4)
    } else if (isWarning || isSuspicious) {
        if (hasLink) {
            if (isUnverifiedUrl) {
                actions.add("Open the official app or website directly instead of tapping the unverified Link.")
            } else {
                actions.add("Exercise extreme caution before opening any link in this message.")
            }
        }
        
        if (asksForOtp) {
            actions.add("Do not share OTP, PIN, or passwords in response to unsolicited requests.")
        }
        
        // Sender verification is highly recommended for suspicious
        actions.add("Verify the sender's identity through official sources before taking any action.")
        
        if (isBankOrUpi || isRefundScam || isBankScam) {
            actions.add("Double-check transaction status directly in your official bank or UPI app.")
        } else if (isPrizeScam || isPrizeOrRefund) {
            actions.add("Do not trust prize claims if you haven't participated in any contest.")
        }
        
        if (isUrgent) {
            actions.add("Avoid rushing; message-created urgency is a common tactic of scammers.")
        }
        
        if (actions.size < 2) {
            actions.add("Consider blocking the sender if you don't recognize them.")
        }
        
        return actions.distinct().take(3)
    } else { // Safe
        if (hasLink) {
            actions.add("The Link appears safe, but remain vigilant on unfamiliar websites.")
        } else {
            actions.add("This message looks safe, but stay cautious with unexpected requests.")
        }
        
        if (actions.size < 2) {
            actions.add("Continue practicing safe sharing and messaging habits.")
        }
        
        return actions.distinct().take(2)
    }
}

data class RiskFactor(
    val name: String,
    val percentage: Int,
    val color: androidx.compose.ui.graphics.Color
)

data class ParsedUrlStatus(
    val originalUrl: String,
    val riskLevel: String,
    val webRiskVerdict: String,
    val phishtankVerdict: String,
    val urlhausVerdict: String,
    val webRiskStatus: String,
    val phishtankStatus: String,
    val urlhausStatus: String,
    val urlscanVerdict: String = "UNVERIFIED",
    val urlscanStatus: String = "UNKNOWN",
    val threatType: String? = null
)

fun parseUrlStatus(statusStr: String, isHindi: Boolean): ParsedUrlStatus? {
    try {
        val json = org.json.JSONObject(statusStr)
        val url = json.optString("original_url", "Unknown")
        val risk = json.optString("risk_level", "Unknown")
        val webRisk = json.optString("web_risk_verdict", "Unknown")
        val phishtank = json.optString("phishtank_verdict", "Unknown")
        val urlhaus = json.optString("urlhaus_verdict", "Unknown")
        val webRiskStatus = json.optString("web_risk_status", "UNKNOWN")
        val phishtankStatus = json.optString("phishtank_status", "UNKNOWN")
        val urlhausStatus = json.optString("urlhaus_status", "UNKNOWN")
        val urlscanVerdict = json.optString("urlscan_verdict", "UNVERIFIED")
        val urlscanStatus = json.optString("urlscan_status", "UNKNOWN")
        val threatType = json.optString("threat_type", "").takeIf { it.isNotEmpty() }
        val parsed = ParsedUrlStatus(
            originalUrl = url,
            riskLevel = risk,
            webRiskVerdict = webRisk,
            phishtankVerdict = phishtank,
            urlhausVerdict = urlhaus,
            webRiskStatus = webRiskStatus,
            phishtankStatus = phishtankStatus,
            urlhausStatus = urlhausStatus,
            urlscanVerdict = urlscanVerdict,
            urlscanStatus = urlscanStatus,
            threatType = threatType
        )
        android.util.Log.d("WebRiskTrace", "10. Value parsed by parseUrlStatus(): originalUrl=$url, webRiskVerdict=$webRisk, webRiskStatus=$webRiskStatus")
        return parsed
    } catch (e: Exception) {
        return null
    }
}
