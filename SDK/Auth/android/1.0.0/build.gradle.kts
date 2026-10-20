// OpenBack App Auth for Android.
// Build + unit tests:  ./gradlew :openback-app-auth-android:assembleRelease :openback-app-auth-android:testDebugUnitTest
// Local Maven repo:    ./gradlew :openback-app-auth-android:publishToMavenLocal   (nothing is published to a registry)
plugins {
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
}
