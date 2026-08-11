package com.skyorigin.threatshieldai

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.google.android.gms.ads.AdListener
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.AdSize
import com.google.android.gms.ads.AdView
import com.google.android.gms.ads.LoadAdError
import android.util.Log

import androidx.compose.foundation.layout.defaultMinSize

@Composable
fun BannerAdComposable(modifier: Modifier = Modifier) {
    val configuration = LocalConfiguration.current
    val context = LocalContext.current
    
    // Screen width minus 32dp for padding (16dp each side)
    val adWidth = maxOf(300, configuration.screenWidthDp - 32)
    var isAdLoaded by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = 60.dp) // Maintain space even if ad fails to load
            .then(
                if (isAdLoaded) {
                    Modifier
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color.White.copy(alpha = 0.05f))
                        .padding(bottom = 8.dp)
                } else {
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                }
            ),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (isAdLoaded) {
            Text(
                text = "Sponsored",
                fontSize = 10.sp,
                color = Color.Gray,
                modifier = Modifier
                    .align(Alignment.Start)
                    .padding(start = 12.dp, top = 6.dp, bottom = 4.dp)
            )
        }
        
        AndroidView(
            modifier = Modifier.fillMaxWidth(),
            factory = { factoryContext ->
                AdView(factoryContext).apply {
                    setAdSize(AdSize.getCurrentOrientationAnchoredAdaptiveBannerAdSize(factoryContext, adWidth))
                    adUnitId = AdConstants.BANNER_AD_UNIT_ID
                    adListener = object : AdListener() {
                        override fun onAdLoaded() {
                            Log.d("AdMob", "Banner ad loaded successfully")
                            isAdLoaded = true
                        }

                        override fun onAdFailedToLoad(error: LoadAdError) {
                            Log.e("AdMob", "Banner ad failed to load: ${error.message} (code: ${error.code}, domain: ${error.domain})")
                            isAdLoaded = false
                        }
                    }
                    loadAd(AdRequest.Builder().build())
                }
            },
            update = {},
            onRelease = { adView ->
                adView.destroy()
            }
        )
    }
}
