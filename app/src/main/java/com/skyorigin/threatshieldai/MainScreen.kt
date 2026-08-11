package com.skyorigin.threatshieldai

import androidx.compose.animation.*
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import com.skyorigin.threatshieldai.ui.theme.premiumShadow
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.skyorigin.threatshieldai.ui.theme.blueGlow
import android.os.Build
import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.res.painterResource

@Composable
fun MainScreen(
    mainNavController: NavController,
    sharedViewModel: ScamLensViewModel
) {
    val bottomNavController = rememberNavController()

    var showFeedbackDialog by remember { mutableStateOf(false) }

    val navBackStackEntry by bottomNavController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route ?: "dashboard"

    LaunchedEffect(currentRoute) {
        if (currentRoute == "dashboard" && sharedViewModel.shouldShowFeedbackPopup()) {
            showFeedbackDialog = true
        }
    }

    LaunchedEffect(sharedViewModel.requestedTabRoute) {
        val targetRoute = sharedViewModel.requestedTabRoute
        if (targetRoute != null) {
            bottomNavController.navigate(targetRoute) {
                popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                launchSingleTop = true
                restoreState = true
            }
            sharedViewModel.requestedTabRoute = null
        }
    }


    if (showFeedbackDialog) {
        FeedbackDialog(
            viewModel = sharedViewModel,
            onDismiss = { showFeedbackDialog = false }
        )
    }
    
    val isDark = com.skyorigin.threatshieldai.ui.theme.LocalIsDark.current
    val currentThemeMode = sharedViewModel.currentThemeMode

    Scaffold(
        bottomBar = {
            val navBackStackEntry by bottomNavController.currentBackStackEntryAsState()
            val currentRoute = navBackStackEntry?.destination?.route ?: "dashboard"

            val glassContainerColor = when (currentThemeMode) {
                ThemeMode.DARK -> Color(0xF20D1117) // Sleek iOS translucent deep dark slate
                ThemeMode.LIGHT -> Color(0xF5F6F8FA) // Translucent clean iOS off-white
                ThemeMode.SYSTEM -> {
                    if (isDark) Color(0xF20D1117) else Color(0xF5F6F8FA)
                }
            }

            val subtleBorderColor = if (isDark) {
                Color(0x1F94A3B8) // Fine border in dark mode
            } else {
                Color(0x0F000000) // Super thin iOS-style light border
            }

            val selectedIndex = when (currentRoute) {
                "dashboard" -> 0
                "history" -> 1
                "scan" -> 2
                "learn" -> 3
                "settings" -> 4
                else -> 0
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(glassContainerColor)
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    // Thin premium top border
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(0.5.dp)
                            .background(subtleBorderColor)
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .navigationBarsPadding()
                            .height(58.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        listOf(
                            NavigationItem("dashboard", "Home", Icons.Rounded.Home),
                            NavigationItem("history", "History", Icons.Rounded.History),
                            NavigationItem("scan", "Analysis", Icons.Rounded.Shield),
                            NavigationItem("learn", "Learn", Icons.Rounded.School),
                            NavigationItem("settings", "Settings", Icons.Rounded.Settings)
                        ).forEachIndexed { index, item ->
                            val isSelected = index == selectedIndex

                            val animatedColor by animateColorAsState(
                                targetValue = if (isSelected) {
                                    if (isDark) Color(0xFF0A84FF) else Color(0xFF007AFF) // Premium iOS System Blue accent
                                } else {
                                    if (isDark) Color(0xFF8E8E93) else Color(0xFF9E9E9E) // iOS style inactive system gray
                                },
                                animationSpec = tween(200),
                                label = "tab_color"
                            )

                            val scale by animateFloatAsState(
                                targetValue = if (isSelected) 1.05f else 1.00f,
                                animationSpec = spring(
                                    dampingRatio = Spring.DampingRatioLowBouncy,
                                    stiffness = Spring.StiffnessMediumLow
                                ),
                                label = "tab_scale"
                            )

                            val iconScale by animateFloatAsState(
                                targetValue = if (isSelected) 1.12f else 1.00f,
                                animationSpec = spring(
                                    dampingRatio = Spring.DampingRatioLowBouncy,
                                    stiffness = Spring.StiffnessMediumLow
                                ),
                                label = "icon_scale"
                            )

                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxHeight()
                                    .clickable(
                                        onClick = {
                                            if (currentRoute != item.route) {
                                                bottomNavController.navigate(item.route) {
                                                    popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                                                    launchSingleTop = true
                                                    restoreState = true
                                                }
                                            }
                                        },
                                        interactionSource = remember { MutableInteractionSource() },
                                        indication = null // Custom tactile feedback to feel purely custom and elegant
                                    ),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(
                                    modifier = Modifier.graphicsLayer(scaleX = scale, scaleY = scale),
                                    horizontalAlignment = Alignment.CenterHorizontally,
                                    verticalArrangement = Arrangement.Center
                                ) {
                                    Icon(
                                        imageVector = item.icon,
                                        contentDescription = item.label,
                                        tint = animatedColor,
                                        modifier = Modifier
                                            .size(23.dp)
                                            .graphicsLayer(scaleX = iconScale, scaleY = iconScale)
                                    )

                                    Spacer(modifier = Modifier.height(2.dp))

                                    Text(
                                        text = item.label,
                                        color = animatedColor,
                                        fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Medium,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontSize = 10.sp,
                                            letterSpacing = (-0.1).sp
                                        ),
                                        maxLines = 1
                                    )

                                    Spacer(modifier = Modifier.height(3.dp))

                                    // Elegant iOS-style micro indicator dot
                                    Box(
                                        modifier = Modifier
                                            .size(3.dp)
                                            .alpha(if (isSelected) 1f else 0f)
                                            .background(
                                                color = if (isDark) Color(0xFF0A84FF) else Color(0xFF007AFF),
                                                shape = CircleShape
                                            )
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = bottomNavController,
            startDestination = "dashboard",
            modifier = Modifier.padding(innerPadding),
            enterTransition = { fadeIn(animationSpec = tween(300)) + slideInHorizontally(initialOffsetX = { 80 }, animationSpec = tween(300)) },
            exitTransition = { fadeOut(animationSpec = tween(300)) + slideOutHorizontally(targetOffsetX = { -80 }, animationSpec = tween(300)) },
            popEnterTransition = { fadeIn(animationSpec = tween(300)) + slideInHorizontally(initialOffsetX = { -80 }, animationSpec = tween(300)) },
            popExitTransition = { fadeOut(animationSpec = tween(300)) + slideOutHorizontally(targetOffsetX = { 80 }, animationSpec = tween(300)) }
        ) {
            composable("dashboard") {
                DashboardScreen(
                    viewModel = sharedViewModel,
                    onNavigateToScan = {
                        bottomNavController.navigate("scan") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToResult = { analysis ->
                        sharedViewModel.currentAnalysisResult = analysis
                        mainNavController.navigate("result")
                    },
                    onNavigateToHistory = {
                        bottomNavController.navigate("history") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToDailyChallenge = {
                        bottomNavController.navigate("learn") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToSettings = {
                        bottomNavController.navigate("settings") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToInventory = {
                        mainNavController.navigate("inventory")
                    }
                )
            }
            composable("scan") {
                HomeScreen(
                    viewModel = sharedViewModel,
                    onNavigateToSettings = {
                        bottomNavController.navigate("settings") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToHistory = {
                        bottomNavController.navigate("history") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToLoading = { text ->
                        sharedViewModel.prepareForScan(text)
                        mainNavController.navigate("loading")
                    }
                )
            }
            composable("history") {
                HistoryScreen(
                    viewModel = sharedViewModel,
                    onBack = {
                        bottomNavController.navigate("dashboard") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToResult = { analysis ->
                        sharedViewModel.currentAnalysisResult = analysis
                        mainNavController.navigate("result")
                    }
                )
            }
            composable("learn") {
                LearnScreen(
                    viewModel = sharedViewModel,
                    onNavigateToChallenge = { mainNavController.navigate("daily_challenge") },
                    onNavigateToAcademy = { mainNavController.navigate("scam_academy") },
                    onNavigateToDailyTip = { mainNavController.navigate("daily_safety_tip") },
                    onNavigateToQuiz = { mainNavController.navigate("quick_quiz") },
                    onNavigateToCommonScams = { mainNavController.navigate("common_scam_examples") },
                    onNavigateToDictionary = { mainNavController.navigate("cyber_dictionary") },
                    onNavigateBack = {
                        bottomNavController.navigate("dashboard") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    }
                )
            }
            composable("settings") {
                val context = androidx.compose.ui.platform.LocalContext.current
                SettingsScreen(
                    viewModel = sharedViewModel,
                    onNavigateToAbout = { mainNavController.navigate("about") },
                    onNavigateToAppearance = { mainNavController.navigate("appearance") },
                    onNavigateToHistory = {
                        bottomNavController.navigate("history") {
                            popUpTo(bottomNavController.graph.startDestinationId) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    onNavigateToDoc = { doc ->
                        LegalConstants.openLegalPortal(context)
                    },
                    onNavigateToFaq = { mainNavController.navigate("faq") }
                )
            }
        }
    }
}

private data class NavigationItem(
    val route: String,
    val label: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
)


