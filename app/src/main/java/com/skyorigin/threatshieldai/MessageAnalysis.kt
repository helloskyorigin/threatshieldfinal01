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
    return VerdictMapper.getVerdictForScore(score).getTitle(isHindi)
}

fun MessageAnalysis.getRiskLevelLabel(isHindi: Boolean): String {
    return VerdictMapper.getVerdictForScore(score).getTitle(isHindi)
}

fun MessageAnalysis.getConfidenceLabel(isHindi: Boolean): String {
    val conf = if (confidence > 0) confidence else 50
    return if (isHindi) {
        when {
            conf >= 80 -> "High (${conf}%)"
            conf >= 50 -> "Medium (${conf}%)"
            else -> "Low (${conf}%)"
        }
    } else {
        when {
            conf >= 80 -> "High (${conf}%)"
            conf >= 50 -> "Medium (${conf}%)"
            else -> "Low (${conf}%)"
        }
    }
}

fun MessageAnalysis.getLocalizedSummary(isHindi: Boolean): String {
    if (summary.isNotEmpty() && 
        !summary.contains("temporarily unavailable") && 
        !summary.contains("अस्थायी रूप से अनुपलब्ध")) {
        return summary
    }
    val st = status.lowercase()
    if (isHindi) {
        return when {
            st.contains("danger") || st.contains("unsafe") || score >= 70 -> {
                "यह संदेश एक खतरनाक घोटाला हो सकता है। इसमें संदिग्ध लिंक और धोखाधड़ी के संकेत मिले हैं।"
            }
            st.contains("suspicious") || score >= 40 -> {
                "यह संदेश पूरी तरह भरोसेमंद नहीं लग रहा है। इसमें सावधानी रखना आवश्यक है।"
            }
            else -> {
                "इस संदेश में कोई घोटाला पैटर्न नहीं मिला है। संदेश सुरक्षित प्रतीत होता है।"
            }
        }
    }
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
    if (isHindi) {
        return when {
            st.contains("danger") || st.contains("unsafe") || score >= 70 -> {
                "संदेश में गंभीर सुरक्षा जोखिम, फर्जी पहचान या डेटा चोरी के संकेत मिले हैं। किसी भी लिंक को न खोलें और निजी जानकारी साझा न करें।"
            }
            st.contains("suspicious") || score >= 40 -> {
                "यह संदेश पूरी तरह सुरक्षित नहीं लग रहा है। इसमें असामान्य दबाव या असत्यापित अनुरोध पाए गए हैं। सावधानी बरतें।"
            }
            else -> {
                "संदेश का सुरक्षा विश्लेषण पूर्ण हुआ। कोई फ़िशिंग लिंक या संदिग्ध पैटर्न नहीं पाया गया, संदेश सुरक्षित प्रतीत होता है।"
            }
        }
    }
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
            actions.add(if (isHindi) "दिए गए Link को बिल्कुल न खोलें, यह एक पुख्ता खतरा है।" else "Do not open the detected Link; it is a confirmed threat.")
            actions.add(if (isHindi) "personal, financial, login, OTP या sensitive information enter न करें।" else "Do not enter personal, financial, login, OTP, or other sensitive information.")
            actions.add(if (isHindi) "आवश्यकता होने पर official channel के माध्यम से sender को verify करें।" else "Verify the sender through an official channel if necessary.")
            actions.add(if (isHindi) "उचित होने पर sender को block और report करें।" else "Block/report the sender when appropriate.")
        } else {
            if (hasLink) {
                actions.add(if (isHindi) "इस message में दिए गए suspicious Link पर click न करें।" else "Do not tap on the suspicious Link in this message.")
            }
            
            if (asksForOtp) {
                actions.add(if (isHindi) "OTP, PIN या Password किसी के साथ share न करें।" else "Never share OTP, PIN, or passwords with anyone.")
            }
            
            if (isBankOrUpi || isRefundScam || isBankScam) {
                actions.add(if (isHindi) "अपनी banking details सुरक्षित रखें और अज्ञात खातों में पैसे transfer न करें।" else "Keep your banking details secure and do not transfer money to unknown accounts.")
            } else if (isPrizeScam || isPrizeOrRefund) {
                actions.add(if (isHindi) "अचानक मिले lottery, cashback या reward के दावों को ignore करें।" else "Ignore claims of unexpected lottery, cashback, or rewards.")
            }
            
            if (asksForVerification || isUrgent) {
                actions.add(if (isHindi) "दबाव या urgency के प्रभाव में आकर credentials update न करें।" else "Do not perform verification or account updates under urgency pressure.")
            }
            
            // Fallbacks to reach at least 2 actions
            if (actions.size < 2) {
                actions.add(if (isHindi) "इस sender को तुरंत block और report करें।" else "Block and report this sender immediately.")
            }
            if (actions.size < 2) {
                actions.add(if (isHindi) "भविष्य में सुरक्षा के लिए इस तरह के संदेशों से दूर रहें।" else "Avoid interacting with similar messages for future safety.")
            }
        }
        
        return actions.distinct().take(4)
    } else if (isWarning || isSuspicious) {
        if (hasLink) {
            if (isUnverifiedUrl) {
                actions.add(if (isHindi) "Unverified Link पर click करने के बजाय official app या website का उपयोग करें।" else "Open the official app or website directly instead of tapping the unverified Link.")
            } else {
                actions.add(if (isHindi) "इस message में मौजूद Link को open करने से पहले सावधानी बरतें।" else "Exercise extreme caution before opening any link in this message.")
            }
        }
        
        if (asksForOtp) {
            actions.add(if (isHindi) "अज्ञात अनुरोधों के जवाब में OTP, PIN या Password share न करें।" else "Do not share OTP, PIN, or passwords in response to unsolicited requests.")
        }
        
        // Sender verification is highly recommended for suspicious
        actions.add(if (isHindi) "कोई भी action लेने से पहले sender की identity को official source से verify करें।" else "Verify the sender's identity through official sources before taking any action.")
        
        if (isBankOrUpi || isRefundScam || isBankScam) {
            actions.add(if (isHindi) "अपने bank या UPI app से transaction status खुद check करें।" else "Double-check transaction status directly in your official bank or UPI app.")
        } else if (isPrizeScam || isPrizeOrRefund) {
            actions.add(if (isHindi) "बिना किसी प्रतियोगिता में भाग लिए मिले इनामों पर विश्वास न करें।" else "Do not trust prize claims if you haven't participated in any contest.")
        }
        
        if (isUrgent) {
            actions.add(if (isHindi) "उतावली करने से बचें, ऐसी urgency messages अक्सर scam हो सकती हैं।" else "Avoid rushing; message-created urgency is a common tactic of scammers.")
        }
        
        if (actions.size < 2) {
            actions.add(if (isHindi) "इस message के sender को block करने पर विचार करें।" else "Consider blocking the sender if you don't recognize them.")
        }
        
        return actions.distinct().take(3)
    } else { // Safe
        if (hasLink) {
            actions.add(if (isHindi) "यह Link सुरक्षित लग रहा है, फिर भी अनजान स्रोतों पर सतर्क रहें।" else "The Link appears safe, but remain vigilant on unfamiliar websites.")
        } else {
            actions.add(if (isHindi) "यह संदेश सुरक्षित लग रहा है, पर unexpected अनुरोधों से हमेशा सावधान रहें।" else "This message looks safe, but stay cautious with unexpected requests.")
        }
        
        if (actions.size < 2) {
            actions.add(if (isHindi) "सुरक्षित संदेश प्रथाओं (Safe sharing practices) का पालन करते रहें।" else "Continue practicing safe sharing and messaging habits.")
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
