package com.skyorigin.threatshieldai

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.border
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material.icons.automirrored.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.skyorigin.threatshieldai.ui.theme.*
import androidx.compose.foundation.Image
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.layout

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: ScamLensViewModel,
    onNavigateToAbout: () -> Unit,
    onNavigateToAppearance: () -> Unit,
    onNavigateToHistory: () -> Unit,
    onNavigateToDoc: (String) -> Unit,
    onNavigateToFaq: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isDark = LocalIsDark.current
    val isHindi = false
    val context = androidx.compose.ui.platform.LocalContext.current

    val textPrimary = MaterialTheme.colorScheme.onBackground
    val textSecondary = MaterialTheme.colorScheme.onSurfaceVariant
    val bgColor = MaterialTheme.colorScheme.background
    val cardBg = MaterialTheme.colorScheme.surface
    val cardBorderColor = MaterialTheme.colorScheme.outlineVariant

    var showLanguageDialog by remember { mutableStateOf(false) }
    var showThemeDialog by remember { mutableStateOf(false) }
    var showClearHistoryDialog by remember { mutableStateOf(false) }
    var showStatsDialog by remember { mutableStateOf(false) }

    var showFeedbackDialogFromSettings by remember { mutableStateOf(false) }
    var feedbackDialogRating by remember { mutableStateOf(0) }
    var feedbackForceForm by remember { mutableStateOf(false) }
    var feedbackPreSelectedCategory by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        AnalyticsManager.getInstance(context).logSettingsOpened()
        AnalyticsManager.getInstance(context).logScreenView("settings")
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Settings",
                        style = TextStyle(
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = textPrimary
                        )
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = bgColor
                )
            )
        },
        containerColor = bgColor,
        modifier = modifier
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {

            // Top Permanent Dark Branding Area
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = Color(0xFF0F172A),
                border = BorderStroke(1.dp, Color(0xFF1E293B))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 12.dp, horizontal = 16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Image(
                        painter = painterResource(id = R.drawable.threat),
                        contentDescription = "ThreatShield AI Logo",
                        modifier = Modifier.size(230.dp),
                        contentScale = ContentScale.Fit
                    )

                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.layout { measurable, constraints ->
                            val placeable = measurable.measure(constraints)
                            val yOffset = (-32).dp.roundToPx()
                            layout(placeable.width, (placeable.height + yOffset).coerceAtLeast(0)) {
                                placeable.placeRelative(0, yOffset)
                            }
                        }
                    ) {
                        Text(
                            text = "ThreatShield AI",
                            style = TextStyle(
                                fontSize = 20.sp,
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.5.sp
                            )
                        )

                        Spacer(modifier = Modifier.height(2.dp))

                        Text(
                            text = "v1.0",
                            style = TextStyle(
                                fontSize = 12.sp,
                                color = Color(0xFF94A3B8),
                                fontWeight = FontWeight.Medium
                            )
                        )
                    }
                }
            }

            // Section 1: Preferences
            Text(
                text = "Preferences",
                style = TextStyle(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = PremiumColors.PrimaryAccent
                )
            )

            com.skyorigin.threatshieldai.ui.theme.PremiumCard {
                SettingsRow(
                    icon = Icons.Rounded.Palette,
                    title = "Theme",
                    subtitle = when (viewModel.currentThemeMode) {
                        ThemeMode.SYSTEM -> "System default"
                        ThemeMode.LIGHT -> "Light"
                        ThemeMode.DARK -> "Dark"
                    },
                    onClick = { showThemeDialog = true },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF8B5CF6)
                )
            }

            // Section 2: Account & Safety
            Text(
                text = "Account & Safety",
                style = TextStyle(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = PremiumColors.PrimaryAccent
                )
            )

            com.skyorigin.threatshieldai.ui.theme.PremiumCard {
                SettingsRow(
                    icon = Icons.Rounded.History,
                    title = "Analysis History",
                    subtitle = "View your past analysis history",
                    onClick = onNavigateToHistory,
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF06B6D4)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.Rounded.DeleteForever,
                    title = "Clear History",
                    subtitle = "Delete all analysis records",
                    onClick = {
                        if (viewModel.analysesHistory.isEmpty()) {
                            android.widget.Toast.makeText(
                                context,
                                "No scan history yet. Complete your first scan to get started.",
                                android.widget.Toast.LENGTH_SHORT
                            ).show()
                        } else {
                            showClearHistoryDialog = true
                        }
                    },
                    textColor = com.skyorigin.threatshieldai.ui.theme.PremiumColors.Danger,
                    subColor = textSecondary,
                    iconColor = Color(0xFFEF4444)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.Rounded.Analytics,
                    title = "Statistics",
                    subtitle = "View security statistics & metrics",
                    onClick = {
                        showStatsDialog = true
                    },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF3B82F6)
                )
            }

            // Section: Feedback & Support
            Text(
                text = "Feedback & Support",
                style = TextStyle(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = PremiumColors.PrimaryAccent
                )
            )

            com.skyorigin.threatshieldai.ui.theme.PremiumCard {
                SettingsRow(
                    icon = Icons.Rounded.Star,
                    title = "Rate ThreatShield AI",
                    subtitle = "Rate and review our app",
                    onClick = {
                        AnalyticsManager.getInstance(context).logRateAppClicked()
                        feedbackDialogRating = 0
                        feedbackForceForm = false
                        feedbackPreSelectedCategory = null
                        showFeedbackDialogFromSettings = true
                    },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFFF59E0B)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.Rounded.BugReport,
                    title = "Report a Bug",
                    subtitle = "Report an issue or error",
                    onClick = {
                        AnalyticsManager.getInstance(context).logReportBugClicked()
                        feedbackDialogRating = 3
                        feedbackForceForm = true
                        feedbackPreSelectedCategory = "Bug Report"
                        showFeedbackDialogFromSettings = true
                    },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFFF97316)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.Rounded.Lightbulb,
                    title = "Request a Feature",
                    subtitle = "Suggest a new feature or improvement",
                    onClick = {
                        AnalyticsManager.getInstance(context).logRequestFeatureClicked()
                        feedbackDialogRating = 4
                        feedbackForceForm = true
                        feedbackPreSelectedCategory = "Feature Request"
                        showFeedbackDialogFromSettings = true
                    },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF8B5CF6)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.Rounded.Feedback,
                    title = "Send Feedback",
                    subtitle = "Share your valuable feedback",
                    onClick = {
                        AnalyticsManager.getInstance(context).logSendFeedbackClicked()
                        feedbackDialogRating = 0
                        feedbackForceForm = false
                        feedbackPreSelectedCategory = null
                        showFeedbackDialogFromSettings = true
                    },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF3B82F6)
                )
            }

            // Section 3: Legal & About
            Text(
                text = "Legal & Info",
                style = TextStyle(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = PremiumColors.PrimaryAccent
                )
            )

            com.skyorigin.threatshieldai.ui.theme.PremiumCard {
                SettingsRow(
                    icon = Icons.Rounded.Gavel,
                    title = "Legal & Privacy Portal",
                    subtitle = "Terms, privacy policy, and safety info",
                    onClick = { onNavigateToDoc("legal_portal") },
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF6366F1)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.AutoMirrored.Rounded.HelpOutline,
                    title = "Frequently Asked Questions (FAQ)",
                    subtitle = "Find answers to common questions",
                    onClick = onNavigateToFaq,
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF06B6D4)
                )
                HorizontalDivider(color = cardBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                SettingsRow(
                    icon = Icons.Rounded.Info,
                    title = "About ThreatShield AI",
                    subtitle = "About the app",
                    onClick = onNavigateToAbout,
                    textColor = textPrimary,
                    subColor = textSecondary,
                    iconColor = Color(0xFF3B82F6)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

        }
    }

    if (showFeedbackDialogFromSettings) {
        FeedbackDialog(
            viewModel = viewModel,
            onDismiss = { showFeedbackDialogFromSettings = false },
            initialRating = feedbackDialogRating,
            forceFormStage = feedbackForceForm,
            preSelectedCategory = feedbackPreSelectedCategory
        )
    }

    // Theme Dialog
    if (showThemeDialog) {
        AlertDialog(
            onDismissRequest = { showThemeDialog = false },
            title = {
                Text(
                    text = "Select Theme",
                    color = textPrimary,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    ThemeMode.values().forEach { mode ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    viewModel.currentThemeMode = mode
                                    showThemeDialog = false
                                }
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = viewModel.currentThemeMode == mode,
                                onClick = {
                                    viewModel.currentThemeMode = mode
                                    showThemeDialog = false
                                }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = when (mode) {
                                    ThemeMode.SYSTEM -> "System default"
                                    ThemeMode.LIGHT -> "Light"
                                    ThemeMode.DARK -> "Dark"
                                },
                                color = textPrimary,
                                fontSize = 16.sp
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showThemeDialog = false }) {
                    Text("Close", color = PremiumColors.PrimaryAccent)
                }
            },
            containerColor = cardBg
        )
    }

    // Clear History Confirmation Dialog
    if (showClearHistoryDialog && viewModel.analysesHistory.isNotEmpty()) {
        AlertDialog(
            onDismissRequest = { showClearHistoryDialog = false },
            title = {
                Text(
                    text = "Clear History?",
                    color = textPrimary,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Text(
                    text = "Are you sure you want to clear all analysis records? This action cannot be undone.",
                    color = textPrimary,
                    fontSize = 15.sp
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.clearAllHistory()
                        showClearHistoryDialog = false
                        android.widget.Toast.makeText(
                            context,
                            "History cleared successfully",
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                    }
                ) {
                    Text(
                        text = "Clear",
                        color = PremiumColors.Danger,
                        fontWeight = FontWeight.Bold
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearHistoryDialog = false }) {
                    Text(
                        text = "Cancel",
                        color = textSecondary
                    )
                }
            },
            containerColor = cardBg
        )
    }

    // Statistics Dialog
    if (showStatsDialog) {
        val history = viewModel.analysesHistory
        val totalScans = history.size
        val scamCount = history.count { it.status.lowercase() == "danger" || it.status.lowercase() == "unsafe" }
        val safeCount = history.count { it.status.lowercase() == "safe" }
        val suspiciousCount = history.count { it.status.lowercase() == "suspicious" }
        val protectionScore = if (totalScans == 0) 0 else ((safeCount.toFloat() / totalScans) * 100).toInt().coerceIn(0, 100)

        val dbFile = context.getDatabasePath("scam_shield_database")
        val dbSizeStr = if (dbFile != null && dbFile.exists()) {
            val sizeInBytes = dbFile.length()
            if (sizeInBytes < 1024) "$sizeInBytes B"
            else "${sizeInBytes / 1024} KB"
        } else {
            "48 KB"
        }

        val appVersion = remember {
            try {
                val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
                packageInfo.versionName ?: "1.0.0"
            } catch (e: Exception) {
                "1.0.0"
            }
        }

        val scoreTextVal = if (totalScans == 0) "--" else "$protectionScore%"

        val labelStatus = "Protection Status"
        val labelLastUpdated = "Last Analysis"

        val status = ProtectionStatusHelper.calculateStatus(history)
        val statusTextVal = when (status) {
            ProtectionStatus.EXCELLENT -> "Excellent"
            ProtectionStatus.GOOD -> "Good"
            ProtectionStatus.NEEDS_ATTENTION -> "Attention"
            ProtectionStatus.HIGH_RISK -> "High Risk"
            ProtectionStatus.UNKNOWN -> "No Scan Data"
        }

        val lastUpdatedVal = if (history.isNotEmpty()) {
            val lastScan = history.maxByOrNull { it.timestamp }
            if (lastScan != null) {
                val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
                sdf.format(java.util.Date(lastScan.timestamp))
            } else {
                "N/A"
            }
        } else {
            "N/A"
        }

        val labelTotal = "Total Scans"
        val labelScam = "Threats Detected"
        val labelSafe = "Safe Messages"
        val labelSuspicious = "Suspicious"
        val labelScore = "Protection Score"
        val labelAppVersion = "App Version"
        val labelDbSize = "Database Size"
        val labelHistoryCount = "History Records"

        AlertDialog(
            onDismissRequest = { showStatsDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Rounded.Analytics,
                        contentDescription = null,
                        tint = PremiumColors.PrimaryAccent,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Security Statistics",
                        color = textPrimary,
                        fontWeight = FontWeight.Bold
                    )
                }
            },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Security Engine Performance Metrics",
                        style = TextStyle(
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = PremiumColors.PrimaryAccent
                        )
                    )

                    val statsList = listOf(
                        Triple(labelStatus, statusTextVal, status.icon),
                        Triple(labelScore, scoreTextVal, Icons.Rounded.Verified),
                        Triple(labelLastUpdated, lastUpdatedVal, Icons.Rounded.Schedule),
                        Triple(labelTotal, totalScans.toString(), Icons.Rounded.QrCodeScanner),
                        Triple(labelScam, scamCount.toString(), Icons.Rounded.GppBad),
                        Triple(labelSafe, safeCount.toString(), Icons.Rounded.CheckCircle),
                        Triple(labelSuspicious, suspiciousCount.toString(), Icons.Rounded.ReportProblem),
                        Triple(labelAppVersion, appVersion, Icons.Rounded.Info),
                        Triple(labelDbSize, dbSizeStr, Icons.Rounded.Storage),
                        Triple(labelHistoryCount, totalScans.toString(), Icons.Rounded.Dns)
                    )

                    statsList.forEach { (label, value, icon) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    color = if (isDark) Color(0xFF1E293B).copy(alpha = 0.5f) else Color(0xFFF1F5F9),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                .padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            val itemColor = if (label == labelStatus) {
                                status.color
                            } else if (label == labelScore) {
                                status.color
                            } else if (label == labelScam) {
                                if (isDark) Color(0xFFF87171) else Color(0xFFDC2626)
                            } else if (label == labelSafe) {
                                Color(0xFF22C55E)
                            } else {
                                textPrimary
                            }
                            val iconColor = if (label == labelStatus) {
                                status.color
                            } else {
                                PremiumColors.PrimaryAccent
                            }
                            Row(
                                modifier = Modifier.weight(0.55f),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Icon(
                                    imageVector = icon,
                                    contentDescription = null,
                                    tint = iconColor,
                                    modifier = Modifier.size(16.dp)
                                )
                                Text(
                                    text = label,
                                    style = TextStyle(
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = textPrimary
                                    ),
                                    maxLines = 2,
                                    softWrap = true
                                )
                            }
                            Text(
                                text = value,
                                style = TextStyle(
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = itemColor,
                                    textAlign = TextAlign.End
                                ),
                                modifier = Modifier.weight(0.45f),
                                maxLines = 1,
                                softWrap = true
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { showStatsDialog = false }
                ) {
                    Text(
                        text = "Close",
                        color = PremiumColors.PrimaryAccent,
                        fontWeight = FontWeight.Bold
                    )
                }
            },
            containerColor = cardBg
        )
    }
}

@Composable
private fun SettingsRow(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    textColor: Color,
    subColor: Color,
    iconColor: Color = PremiumColors.PrimaryAccent
) {
    val isDark = LocalIsDark.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(iconColor.copy(alpha = if (isDark) 0.16f else 0.08f), RoundedCornerShape(10.dp))
                .border(BorderStroke(1.dp, iconColor.copy(alpha = 0.25f)), RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = iconColor,
                modifier = Modifier.size(20.dp)
            )
        }
        Spacer(modifier = Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1.0f)) {
            Text(
                text = title,
                style = TextStyle(
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = textColor
                )
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = TextStyle(
                    fontSize = 12.sp,
                    color = subColor
                )
            )
        }
        Icon(
            imageVector = Icons.Rounded.ChevronRight,
            contentDescription = "Go",
            tint = subColor,
            modifier = Modifier.size(20.dp)
        )
    }
}
