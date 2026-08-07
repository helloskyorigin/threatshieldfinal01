# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# Preserve line numbers and source files for readable stack traces in crash reports (like Firebase Crashlytics)
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod,Deprecated,*Annotation*

# --- ThreatShield AI Application Rules ---
# Keep all application classes to avoid any runtime reflection, Room, or serialization crashes
-keep class com.skyorigin.threatshieldai.** { *; }
-keep interface com.skyorigin.threatshieldai.** { *; }
-keep enum com.skyorigin.threatshieldai.** { *; }

# --- AndroidX Jetpack & Compose Rules ---
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**
-keep class androidx.navigation.** { *; }
-dontwarn androidx.navigation.**
-keep class androidx.lifecycle.** { *; }
-dontwarn androidx.lifecycle.**

# --- Room Database Rules ---
-keep class androidx.room.RoomDatabase { *; }
-keep class * extends androidx.room.RoomDatabase { *; }
-keep class * extends androidx.room.SharedSQLiteStatement { *; }
-dontwarn androidx.room.**

# --- WorkManager Rules ---
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}
-dontwarn androidx.work.**

# --- AdMob & Google Play Services Ads Rules ---
-keep class com.google.android.gms.ads.** { *; }
-keep interface com.google.android.gms.ads.** { *; }
-dontwarn com.google.android.gms.ads.**
-keep class com.google.android.ump.** { *; }
-dontwarn com.google.android.ump.**

# --- Firebase Rules ---
-keep class com.google.firebase.** { *; }
-dontwarn com.google.firebase.**

# --- OkHttp & Okio Rules ---
-keep class okhttp3.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-dontwarn org.codehaus.mojo.animal_sniffer.**

# OkHttp platform optional dependencies
-dontwarn org.bouncycastle.jsse.**
-dontwarn org.bouncycastle.provider.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**

# --- Coroutines Rules ---
-keep class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**
