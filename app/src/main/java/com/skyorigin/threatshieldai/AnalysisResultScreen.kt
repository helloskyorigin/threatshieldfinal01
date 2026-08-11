package com.skyorigin.threatshieldai

import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.skyorigin.threatshieldai.ui.theme.LocalIsDark
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AnalysisResultScreen(
    modifier: Modifier = Modifier,
    analysis: MessageAnalysis,
    isHindi: Boolean = false,
    onBack: () -> Unit = {},
    onAnalyzeAnother: () -> Unit = {}
) {
    val context = LocalContext.current
    val isDark = LocalIsDark.current

    // Premium Color Tokens
    val bgColor = if (isDark) Color(0xFF0F172A) else Color(0xFFF8FAFC)
    val cardBg = if (isDark) Color(0xFF1E293B) else Color.White
    val cardBorder = if (isDark) Color(0xFF334155) else Color(0xFFE2E8F0)

    val textPrimary = if (isDark) Color(0xFFF8FAFC) else Color(0xFF0F172A)
    val textSecondary = if (isDark) Color(0xFF94A3B8) else Color(0xFF64748B)

    val primaryBlue = Color(0xFF2563EB)
    val dangerRed = Color(0xFFEF4444)
    val warningOrange = Color(0xFFF59E0B)
    val safeGreen = Color(0xFF22C55E)

    val verdictInfo = VerdictMapper.getVerdictForScore(analysis.score)
    val riskColor = verdictInfo.color
    val riskTitle = verdictInfo.titleEn

    val isDanger = analysis.score >= 70
    val isSuspicious = analysis.score in 40..69
    val isSafe = analysis.score < 40
    val isWarning = isSuspicious
    val isUnableToDetermine = false

    // Animation States
    var animateIn by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        animateIn = true
    }

    val alpha by animateFloatAsState(
        targetValue = if (animateIn) 1f else 0f,
        animationSpec = tween(500),
        label = "alpha"
    )
    val offsetY by animateDpAsState(
        targetValue = if (animateIn) 0.dp else 16.dp,
        animationSpec = tween(500, easing = FastOutSlowInEasing),
        label = "offsetY"
    )

    var isGeneratingPdf by remember { mutableStateOf(false) }

    var showUnverifiedDialog by remember { mutableStateOf(false) }
    var urlToOpen by remember { mutableStateOf("") }
    var showDangerousBlockedDialog by remember { mutableStateOf(false) }
    var blockedUrlReason by remember { mutableStateOf("") }

    val handleUrlClick: (String, String) -> Unit = { url, riskLevel ->
        val uppercaseRisk = riskLevel.uppercase()
        if (uppercaseRisk == "DANGER" || uppercaseRisk == "MALICIOUS") {
            blockedUrlReason = url
            showDangerousBlockedDialog = true
        } else if (uppercaseRisk == "SAFE" || uppercaseRisk == "NO_KNOWN_THREAT") {
            try {
                val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))
                context.startActivity(intent)
            } catch (e: Exception) {
                Toast.makeText(context, "Unable to open URL", Toast.LENGTH_SHORT).show()
            }
        } else {
            urlToOpen = url
            showUnverifiedDialog = true
        }
    }

    val savePdfLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/pdf")
    ) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.openOutputStream(uri)?.use { outputStream ->
                    ReportExportHelper.writePdfReportToStream(context, analysis, isHindi, outputStream)
                }
                Toast.makeText(context, "PDF saved successfully.", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Unable to save PDF. Please try again.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    val formattedDate = remember {
        SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault()).format(Date(analysis.timestamp))
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = bgColor,
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "Scan Result",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Black,
                            color = textPrimary,
                            letterSpacing = 0.5.sp
                        )
                        Text(
                            text = "Scanned on $formattedDate",
                            fontSize = 11.sp,
                            color = textSecondary,
                            fontWeight = FontWeight.Medium
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Rounded.ArrowBack,
                            contentDescription = "Back",
                            tint = textPrimary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                },
                actions = {
                    Icon(
                        imageVector = Icons.Rounded.VerifiedUser,
                        contentDescription = "Shield",
                        tint = textPrimary,
                        modifier = Modifier.padding(end = 8.dp).size(20.dp)
                    )
                    var showDropdown by remember { mutableStateOf(false) }
                    IconButton(onClick = { showDropdown = true }) {
                        Icon(
                            imageVector = Icons.Rounded.MoreVert,
                            contentDescription = "Options",
                            tint = textPrimary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    DropdownMenu(
                        expanded = showDropdown,
                        onDismissRequest = { showDropdown = false },
                        modifier = Modifier.background(cardBg).border(1.dp, cardBorder, RoundedCornerShape(12.dp))
                    ) {
                        DropdownMenuItem(
                            text = { Text("Download PDF", fontWeight = FontWeight.Medium) },
                            onClick = {
                                showDropdown = false
                                savePdfLauncher.launch("ThreatShield_Scan_Report_${System.currentTimeMillis()}.pdf")
                            },
                            leadingIcon = { Icon(Icons.Rounded.PictureAsPdf, contentDescription = null, tint = primaryBlue) }
                        )
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = bgColor
                )
            )
        },
        bottomBar = {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .alpha(alpha),
                color = bgColor,
                tonalElevation = 6.dp,
                shadowElevation = 8.dp,
                border = BorderStroke(1.dp, cardBorder.copy(alpha = 0.5f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(
                        onClick = {
                            if (!isGeneratingPdf) {
                                isGeneratingPdf = true
                                Toast.makeText(context, "Preparing PDF report...", Toast.LENGTH_SHORT).show()
                                ReportExportHelper.shareReportAsPdf(context, analysis, isHindi)
                                isGeneratingPdf = false
                            }
                        },
                        modifier = Modifier.weight(1f).height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, cardBorder),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = textPrimary),
                        contentPadding = PaddingValues(horizontal = 4.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Share,
                            contentDescription = "Share",
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Share",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    OutlinedButton(
                        onClick = {
                            savePdfLauncher.launch("ThreatShield_Scan_Report_${System.currentTimeMillis()}.pdf")
                        },
                        modifier = Modifier.weight(1f).height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, cardBorder),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = textPrimary),
                        contentPadding = PaddingValues(horizontal = 4.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.PictureAsPdf,
                            contentDescription = "PDF",
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "PDF",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Button(
                        onClick = onAnalyzeAnother,
                        modifier = Modifier.weight(1.2f).height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isDark) Color(0xFF38BDF8) else Color(0xFF1E293B),
                            contentColor = if (isDark) Color(0xFF0F172A) else Color.White
                        ),
                        contentPadding = PaddingValues(horizontal = 4.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.DocumentScanner,
                            contentDescription = "Scan",
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Scan Again",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.ExtraBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .alpha(alpha)
                .offset(y = offsetY),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Spacer(modifier = Modifier.height(2.dp))

            // 1. UNIFIED HERO CARD (Score Gauge + Status + AI Summary all-in-one)
            val heroBgTint = riskColor.copy(alpha = 0.06f)
            val heroBorder = riskColor.copy(alpha = 0.15f)
            val aiExplanation = sanitizeText(analysis.getLocalizedExplain15(isHindi))
            
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = heroBgTint),
                border = BorderStroke(1.dp, heroBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Gauge (LEFT)
                        Box(
                            modifier = Modifier.size(76.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Canvas(modifier = Modifier.size(64.dp)) {
                                drawArc(
                                    color = riskColor.copy(alpha = 0.15f),
                                    startAngle = 135f,
                                    sweepAngle = 270f,
                                    useCenter = false,
                                    style = Stroke(width = 6.dp.toPx(), cap = StrokeCap.Round)
                                )
                            }

                            val scoreProgress = remember { Animatable(0f) }
                            LaunchedEffect(analysis.score) {
                                scoreProgress.animateTo(
                                    targetValue = analysis.score / 100f,
                                    animationSpec = tween(1200, easing = FastOutSlowInEasing)
                                )
                            }

                            Canvas(modifier = Modifier.size(64.dp)) {
                                drawArc(
                                    color = riskColor,
                                    startAngle = 135f,
                                    sweepAngle = 270f * scoreProgress.value,
                                    useCenter = false,
                                    style = Stroke(width = 6.dp.toPx(), cap = StrokeCap.Round)
                                )
                            }

                            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.offset(y = 2.dp)) {
                                Text(
                                    text = "${analysis.score}",
                                    fontSize = 24.sp,
                                    fontWeight = FontWeight.Black,
                                    color = textPrimary,
                                    lineHeight = 24.sp
                                )
                                Text(
                                    text = "/100",
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = textSecondary,
                                    modifier = Modifier.offset(y = (-2).dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.width(12.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = riskColor,
                                    modifier = Modifier.size(18.dp)
                                ) {
                                    Icon(
                                        imageVector = verdictInfo.icon,
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.padding(2.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = riskTitle,
                                    color = riskColor,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 0.5.sp
                                )
                            }
                            
                            Spacer(modifier = Modifier.height(4.dp))
                            
                            val verdictSentence = verdictInfo.subtitleEn
                            
                            Text(
                                text = verdictSentence,
                                color = textPrimary,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                lineHeight = 16.sp
                            )
                            
                            Spacer(modifier = Modifier.height(6.dp))
                            
                            val displayConfidence = if (analysis.confidence > 0) analysis.confidence else 85

                            // Pills Row
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (analysis.scamType.isNotEmpty() && analysis.scamType != "Unknown" && analysis.scamType != "None") {
                                    val shortenedType = if (analysis.scamType.length > 15) {
                                        analysis.scamType.take(12) + "..."
                                    } else {
                                        analysis.scamType
                                    }
                                    Surface(
                                        color = riskColor.copy(alpha = 0.1f),
                                        shape = RoundedCornerShape(100.dp)
                                    ) {
                                        Text(
                                            text = shortenedType,
                                            color = riskColor,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                                Surface(
                                    color = primaryBlue.copy(alpha = 0.1f),
                                    shape = RoundedCornerShape(100.dp)
                                ) {
                                    Text(
                                        text = "AI Confidence: $displayConfidence%",
                                        color = primaryBlue,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                    )
                                }
                            }
                        }
                    }

                    // Seamless integrated AI summary section
                    if (aiExplanation.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        HorizontalDivider(color = heroBorder, thickness = 0.5.dp)
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(
                            verticalAlignment = Alignment.Top,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(28.dp)
                                    .background(primaryBlue.copy(alpha = 0.1f), RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.SmartToy,
                                    contentDescription = "AI Summary",
                                    tint = primaryBlue,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "AI Security Summary",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = primaryBlue
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = aiExplanation,
                                    fontSize = 11.sp,
                                    color = textPrimary.copy(alpha = 0.9f),
                                    fontWeight = FontWeight.Medium,
                                    lineHeight = 15.sp
                                )
                            }
                        }
                    }
                }
            }

            // 3. LINK SECURITY CARD (Google Web Risk Only)
            val parsedUrls = analysis.urlStatuses
                .filter { !it.startsWith("METADATA:") }
                .mapNotNull { parseUrlStatus(it, isHindi) }
                .distinctBy { UrlDetectionEngine.normalizeUrl(it.originalUrl) }
                .sortedBy { 
                    when (it.riskLevel.uppercase()) {
                        "MALICIOUS", "DANGER" -> 0
                        "UNVERIFIED", "UNKNOWN", "FAILED", "TIMEOUT" -> 1
                        else -> 2
                    }
                }

            if (false && parsedUrls.isNotEmpty()) {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = cardBg),
                    border = BorderStroke(1.dp, cardBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Link,
                                contentDescription = "Link Security",
                                tint = primaryBlue,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "Link Security",
                                color = textPrimary,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Black
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        parsedUrls.forEachIndexed { index, urlStatus ->
                            if (index > 0) {
                                Spacer(modifier = Modifier.height(8.dp))
                                HorizontalDivider(color = cardBorder.copy(alpha = 0.5f), thickness = 0.5.dp)
                                Spacer(modifier = Modifier.height(8.dp))
                            }

                            android.util.Log.d("WebRiskTrace", "11. webRiskStatus received by AnalysisResultScreen: ${urlStatus.webRiskStatus}")
                            val isFailed = urlStatus.webRiskStatus != "OK"
                            val reason = if (isFailed) "webRiskStatus is not OK ('${urlStatus.webRiskStatus}'), selecting CHECK UNAVAILABLE" else "webRiskStatus is OK, proceeding to threat/safe check"
                            android.util.Log.d("WebRiskTrace", "12. UI evaluation: isFailed=$isFailed (webRiskStatus='${urlStatus.webRiskStatus}' != 'OK'), reason=$reason")
                            val isThreat = !isFailed && urlStatus.webRiskVerdict.uppercase() in listOf("MALICIOUS", "DANGER")

                            val resultState = when {
                                isFailed -> WebRiskUiResult(
                                    label = "CHECK UNAVAILABLE",
                                    subtitle = "Google Web Risk check unavailable for this URL.",
                                    color = warningOrange,
                                    icon = Icons.Rounded.GppMaybe
                                )
                                isThreat -> WebRiskUiResult(
                                    label = "THREAT FOUND",
                                    subtitle = urlStatus.threatType?.takeIf { it.isNotEmpty() } ?: "Threat detected by Google Web Risk",
                                    color = dangerRed,
                                    icon = Icons.Rounded.GppBad
                                )
                                else -> WebRiskUiResult(
                                    label = "NO KNOWN THREAT FOUND",
                                    subtitle = "Google Web Risk found no known threat for this URL.",
                                    color = safeGreen,
                                    icon = Icons.Rounded.GppGood
                                )
                            }

                            Surface(
                                color = resultState.color.copy(alpha = 0.06f),
                                shape = RoundedCornerShape(10.dp),
                                border = BorderStroke(1.dp, resultState.color.copy(alpha = 0.2f)),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        handleUrlClick(urlStatus.originalUrl, urlStatus.riskLevel)
                                    }
                            ) {
                                Column(
                                    modifier = Modifier.fillMaxWidth().padding(10.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        val displayUrl = try {
                                            val uri = java.net.URI(urlStatus.originalUrl)
                                            val host = uri.host ?: urlStatus.originalUrl
                                            val path = uri.path ?: ""
                                            if (path.length > 20) {
                                                host + path.take(15) + "..."
                                            } else {
                                                host + path
                                            }
                                        } catch (e: Exception) {
                                            urlStatus.originalUrl
                                        }

                                        Text(
                                            text = displayUrl,
                                            fontSize = 12.sp,
                                            color = textPrimary,
                                            fontWeight = FontWeight.Bold,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Icon(
                                            imageVector = Icons.Rounded.OpenInNew,
                                            contentDescription = "Open Link",
                                            tint = textSecondary,
                                            modifier = Modifier.size(14.dp)
                                        )
                                    }

                                    Spacer(modifier = Modifier.height(6.dp))
                                    HorizontalDivider(color = resultState.color.copy(alpha = 0.15f), thickness = 0.5.dp)
                                    Spacer(modifier = Modifier.height(6.dp))

                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Icon(
                                            imageVector = resultState.icon,
                                            contentDescription = null,
                                            tint = resultState.color,
                                            modifier = Modifier.size(20.dp)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Column {
                                            Text(
                                                text = resultState.label,
                                                color = resultState.color,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Black
                                            )
                                            Text(
                                                text = resultState.subtitle,
                                                color = textPrimary.copy(alpha = 0.8f),
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.Medium,
                                                lineHeight = 12.sp
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 4. WHY THIS RESULT CARD (Transformed, human-readable reasons, max 3)
            val whyBgTint = when {
                isDanger -> dangerRed.copy(alpha = 0.04f)
                isWarning || isSuspicious -> warningOrange.copy(alpha = 0.04f)
                isUnableToDetermine -> Color(0xFF94A3B8).copy(alpha = 0.04f)
                else -> safeGreen.copy(alpha = 0.04f)
            }
            val whyBorder = when {
                isDanger -> dangerRed.copy(alpha = 0.12f)
                isWarning || isSuspicious -> warningOrange.copy(alpha = 0.12f)
                isUnableToDetermine -> Color(0xFF94A3B8).copy(alpha = 0.12f)
                else -> safeGreen.copy(alpha = 0.12f)
            }
            
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = whyBgTint),
                border = BorderStroke(1.dp, whyBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Rounded.Lightbulb,
                            contentDescription = "Why",
                            tint = when {
                                isDanger -> dangerRed
                                isWarning || isSuspicious -> warningOrange
                                isUnableToDetermine -> Color(0xFF94A3B8)
                                else -> safeGreen
                            },
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Why This Result?",
                            color = textPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Black
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    val finalReasons = if (analysis.reasons.isNotEmpty()) {
                        analysis.reasons.take(5).map { item ->
                            val cleanItem = item.removePrefix("✕ ").removePrefix("✓ ").removePrefix("• ").trim()
                            val prefix = when {
                                isDanger -> "✕ "
                                isWarning || isSuspicious -> "• "
                                isUnableToDetermine -> "• "
                                else -> "✓ "
                            }
                            "$prefix$cleanItem"
                        }
                    } else when {
                        isDanger -> {
                            val r1 = if (analysis.links.isNotEmpty()) {
                                val hasMalicious = parsedUrls.any { it.riskLevel.uppercase() in listOf("MALICIOUS", "DANGER") }
                                if (hasMalicious) {
                                    "✕ Known dangerous Link detected"
                                } else {
                                    "✕ Highly suspicious Link detected"
                                }
                            } else {
                                val cleanType = analysis.scamType.lowercase()
                                if (cleanType.contains("bank") || cleanType.contains("impersonat")) {
                                    "✕ Severe banking impersonation attempt detected"
                                } else if (cleanType.contains("otp") || cleanType.contains("credential") || cleanType.contains("chori") || cleanType.contains("चोरी")) {
                                    "✕ High-risk credential/OTP theft pattern found"
                                } else {
                                    "✕ Risky unauthorized requests detected"
                                }
                            }
                            val r2 = "✕ Strong scam behavior found in the message"
                            val r3 = "✕ Message attempts a risky or sensitive action"
                            listOf(r1, r2, r3)
                        }
                        isWarning || isSuspicious -> {
                            val r1 = "• Some suspicious behavior detected"
                            val r2 = if (analysis.links.isNotEmpty()) {
                                val hasMalicious = parsedUrls.any { it.riskLevel.uppercase() in listOf("MALICIOUS", "DANGER") }
                                val hasUnverified = parsedUrls.any { it.riskLevel.uppercase() in listOf("UNVERIFIED", "UNKNOWN") }
                                if (hasMalicious) {
                                    "• Dangerous or blacklisted Link found"
                                } else if (hasUnverified) {
                                    "• Unverified link requiring extreme caution"
                                } else {
                                    "• Link requires verification before clicking"
                                }
                            } else {
                                "• Sender or request could not be fully verified"
                            }
                            val r3 = "• Caution is recommended before taking action"
                            listOf(r1, r2, r3)
                        }
                        isUnableToDetermine -> {
                            val r1 = "• Insufficient message context for full analysis"
                            val r2 = if (analysis.links.isNotEmpty()) {
                                "• Link reputation is unverified or offline"
                            } else {
                                "• No links or contact details to verify"
                            }
                            val r3 = "• Caution is advised for unsolicited messages"
                            listOf(r1, r2, r3)
                        }
                        else -> { // SAFE
                            val r1 = "✓ No strong scam behavior found"
                            val r2 = if (analysis.links.isNotEmpty()) {
                                "✓ No known Link threat detected"
                            } else {
                                "✓ No Link detected in the message"
                            }
                            val r3 = "✓ Message appears informational, not requesting sensitive action"
                            listOf(r1, r2, r3)
                        }
                    }
                    
                    finalReasons.forEachIndexed { index, reason ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(vertical = 4.dp)
                        ) {
                            val (icon, iconColor, displayText) = when {
                                reason.startsWith("✕ ") -> Triple(Icons.Rounded.Close, dangerRed, reason.substring(2))
                                reason.startsWith("✓ ") -> Triple(Icons.Rounded.Check, safeGreen, reason.substring(2))
                                reason.startsWith("• ") -> {
                                    val color = if (isUnableToDetermine) Color(0xFF94A3B8) else warningOrange
                                    Triple(Icons.Rounded.FiberManualRecord, color, reason.substring(2))
                                }
                                else -> Triple(Icons.Rounded.Info, riskColor, reason)
                            }
                            Icon(
                                imageVector = icon,
                                contentDescription = null,
                                tint = iconColor,
                                modifier = Modifier.size(if (icon == Icons.Rounded.FiberManualRecord) 10.dp else 16.dp).let {
                                    if (icon == Icons.Rounded.FiberManualRecord) {
                                        it.padding(horizontal = 3.dp)
                                    } else it
                                }
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = displayText,
                                color = textPrimary.copy(alpha = 0.9f),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.weight(1f),
                                lineHeight = 15.sp
                            )
                        }
                    }
                }
            }

            // 5. RECOMMENDED ACTIONS CARD (Maximum 2 dynamic actions, compact tint)
            val recBgTint = when {
                isDanger -> dangerRed.copy(alpha = 0.04f)
                isWarning || isSuspicious -> warningOrange.copy(alpha = 0.04f)
                isUnableToDetermine -> Color(0xFF94A3B8).copy(alpha = 0.04f)
                else -> safeGreen.copy(alpha = 0.04f)
            }
            val recBorder = when {
                isDanger -> dangerRed.copy(alpha = 0.12f)
                isWarning || isSuspicious -> warningOrange.copy(alpha = 0.12f)
                isUnableToDetermine -> Color(0xFF94A3B8).copy(alpha = 0.12f)
                else -> safeGreen.copy(alpha = 0.12f)
            }
            
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = recBgTint),
                border = BorderStroke(1.dp, recBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            shape = CircleShape,
                            color = when {
                                isDanger -> dangerRed
                                isWarning || isSuspicious -> warningOrange
                                isUnableToDetermine -> Color(0xFF94A3B8)
                                else -> safeGreen
                            },
                            modifier = Modifier.size(20.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Check,
                                contentDescription = "Recommended Actions",
                                tint = Color.White,
                                modifier = Modifier.padding(3.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Recommended Actions",
                            color = textPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Black
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    val actionItems = analysis.getLocalAdvice(isHindi)
                    
                    actionItems.forEachIndexed { idx, action ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(vertical = 4.dp)
                        ) {
                            val actionIcon = when {
                                isDanger && idx == 0 -> Icons.Rounded.Block
                                isDanger && idx == 1 -> Icons.Rounded.LockReset
                                isWarning || isSuspicious -> Icons.Rounded.GppMaybe
                                isUnableToDetermine -> Icons.Rounded.HelpOutline
                                else -> Icons.Rounded.CheckCircleOutline
                            }
                            val actionColor = when {
                                isDanger -> dangerRed
                                isWarning || isSuspicious -> warningOrange
                                isUnableToDetermine -> Color(0xFF94A3B8)
                                else -> safeGreen
                            }
                            Icon(
                                imageVector = actionIcon,
                                contentDescription = null,
                                tint = actionColor,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = action,
                                color = textPrimary.copy(alpha = 0.9f),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                lineHeight = 15.sp
                            )
                        }
                    }
                }
            }

            // 5. ABOUT THIS RESULT NOTE (Premium info card)
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isDark) Color(0xFF1E293B).copy(alpha = 0.5f) else Color(0xFFF1F5F9)
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = if (isDark) Color(0xFF334155).copy(alpha = 0.5f) else Color(0xFFE2E8F0)
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Info,
                        contentDescription = null,
                        tint = textSecondary,
                        modifier = Modifier.size(16.dp).offset(y = 1.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "About this result",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = textPrimary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Analyzes message content and checks links for known phishing or malicious threats. This is not a full website scan, and results may not always be accurate.",
                            fontSize = 11.sp,
                            color = textSecondary,
                            lineHeight = 15.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        if (showUnverifiedDialog) {
            AlertDialog(
                onDismissRequest = { showUnverifiedDialog = false },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Rounded.GppMaybe,
                            contentDescription = "Unverified Link",
                            tint = warningOrange,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Unverified Link",
                            fontWeight = FontWeight.Bold,
                            color = textPrimary
                        )
                    }
                },
                text = {
                    Text(
                        text = "This link could not be fully verified by the available security sources.\n\nContinue only if you trust the source.",
                        color = textSecondary,
                        fontSize = 14.sp
                    )
                },
                confirmButton = {
                    Button(
                        onClick = {
                            showUnverifiedDialog = false
                            try {
                                val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(urlToOpen))
                                context.startActivity(intent)
                            } catch (e: Exception) {
                                Toast.makeText(context, "Unable to open URL", Toast.LENGTH_SHORT).show()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = primaryBlue)
                    ) {
                        Text("Open Anyway", fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(
                        onClick = { showUnverifiedDialog = false },
                        colors = ButtonDefaults.textButtonColors(contentColor = textSecondary)
                    ) {
                        Text("Cancel")
                    }
                },
                containerColor = cardBg,
                shape = RoundedCornerShape(20.dp)
            )
        }

        if (showDangerousBlockedDialog) {
            AlertDialog(
                onDismissRequest = { showDangerousBlockedDialog = false },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Rounded.GppBad,
                            contentDescription = "Dangerous Link Blocked",
                            tint = dangerRed,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Dangerous Link Blocked",
                            fontWeight = FontWeight.Bold,
                            color = textPrimary
                        )
                    }
                },
                text = {
                    Column {
                        Text(
                            text = "Opening is disabled for safety",
                            fontWeight = FontWeight.Bold,
                            color = dangerRed,
                            fontSize = 15.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "This link is classified as a known security threat (Known threat). Opening this link is disabled to protect your device and data.",
                            color = textSecondary,
                            fontSize = 14.sp
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = { showDangerousBlockedDialog = false },
                        colors = ButtonDefaults.buttonColors(containerColor = dangerRed)
                    ) {
                        Text("OK", fontWeight = FontWeight.Bold)
                    }
                },
                containerColor = cardBg,
                shape = RoundedCornerShape(20.dp)
            )
        }
    }
}

@Composable
fun ProviderCell(name: String, verdict: String, status: String, isHindi: Boolean = false, modifier: Modifier = Modifier) {
    val isDark = LocalIsDark.current
    
    val localizedName = when (name) {
        "Web Risk" -> "Threat Database"
        "PhishTank" -> "Phishing Check"
        "URLhaus" -> "Malware Check"
        else -> name
    }

    val isMissingKey = status.uppercase() in listOf("MISSING_KEY", "NOT_CONFIGURED", "UNAUTHORIZED")

    val isFailed = status.uppercase() in listOf("FAILED", "TIMEOUT", "SCAN_FAILED", "ERROR", "UNAVAILABLE", "NETWORK_ERROR", "API_ERROR", "RATE_LIMIT") ||
                   verdict.uppercase() in listOf("FAILED", "TIMEOUT", "SCAN_FAILED", "ERROR", "UNAVAILABLE")

    val isSkipped = status.uppercase() in listOf("SCAN_SKIPPED_PRIVACY", "BEHAVIORAL_SCAN_SKIPPED_PRIVACY") ||
                    verdict.uppercase() in listOf("SCAN_SKIPPED_PRIVACY", "BEHAVIORAL_SCAN_SKIPPED_PRIVACY")

    val isMalicious = verdict.uppercase() in listOf("MALICIOUS", "DANGER", "PHISHING", "MALWARE")

    val displayLabel = when {
        isSkipped -> "Skipped (Privacy)"
        isMissingKey -> "Key Not Configured"
        isFailed -> "Database Unavailable"
        isMalicious -> "Threat"
        else -> "No Known Threat Found"
    }
    
    val displayColor = when {
        isSkipped -> Color(0xFF3B82F6)
        isMissingKey -> Color(0xFF64748B)
        isFailed -> Color(0xFFF59E0B)
        isMalicious -> Color(0xFFEF4444)
        else -> Color(0xFF22C55E)
    }
    
    val cellBg = if (isDark) Color(0xFF1E293B) else Color(0xFFF8FAFC)
    val cellBorder = if (isDark) Color(0xFF334155) else Color(0xFFE2E8F0)
    
    Column(
        modifier = modifier
            .background(cellBg, RoundedCornerShape(8.dp))
            .border(1.dp, cellBorder, RoundedCornerShape(8.dp))
            .padding(vertical = 6.dp, horizontal = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = localizedName,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            color = if (isDark) Color(0xFF94A3B8) else Color(0xFF64748B),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = displayLabel,
            fontSize = 10.sp,
            fontWeight = FontWeight.Black,
            color = displayColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

fun mapSignalToReason(signal: String, isHindi: Boolean = false): String {
    val clean = signal.trim().lowercase()
    if (clean.isBlank()) return ""
    
    val words = clean.split("\\s+".toRegex())
    if (words.size >= 4) {
        return sanitizeText(signal)
    }
    return when {
        clean.contains("win") || clean.contains("won") || clean.contains("winner") || clean.contains("prize") || 
        clean.contains("$") || clean.contains("reward") || clean.contains("cash") || clean.contains("money") ||
        clean.contains("crore") || clean.contains("lakh") || clean.contains("lottery") -> {
            "Unexpected cash prize claim"
        }
        clean.contains("click") || clean.contains("open") || clean.contains("visit") || clean.contains("link") || 
        clean.contains("url") || clean.contains("website") || clean.contains("http") -> {
            "Asks you to open a link"
        }
        clean.contains("urgent") || clean.contains("urgency") || clean.contains("now") || clean.contains("immediately") || 
        clean.contains("expire") || clean.contains("blocked") || clean.contains("suspend") -> {
            "Creates urgency or pressure"
        }
        clean.contains("verify") || clean.contains("verification") || clean.contains("kyc") || clean.contains("update") -> {
            "Requests account verification"
        }
        clean.contains("otp") || clean.contains("pin") || clean.contains("password") || clean.contains("credential") || 
        clean.contains("private") || clean.contains("personal") || clean.contains("info") || clean.contains("card") || 
        clean.contains("bank") || clean.contains("finance") || clean.contains("credit") || clean.contains("cvv") -> {
            "Requests sensitive or private information"
        }
        clean.contains("claim") || clean.contains("redeem") || clean.contains("offer") || clean.contains("gift") -> {
            "Encourages you to claim a reward"
        }
        else -> sanitizeText(signal)
    }
}

fun sanitizeText(text: String): String {
    return text.replace("(?i)gpt-oss".toRegex(), "ThreatShield AI")
               .replace("(?i)gpt".toRegex(), "AI")
               .replace("(?i)groq".toRegex(), "AI Engine")
               .replace("(?i)llama".toRegex(), "AI Model")
}

data class WebRiskUiResult(
    val label: String,
    val subtitle: String,
    val color: Color,
    val icon: ImageVector
)

