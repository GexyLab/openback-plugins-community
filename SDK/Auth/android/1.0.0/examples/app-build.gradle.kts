// The app module's build.gradle.kts (excerpt).
android {
    defaultConfig {
        applicationId = "com.example.app"
        // The scheme of the redirect URI registered in the pool: com.example.app:/oauth2redirect
        manifestPlaceholders["openbackAppAuthRedirectScheme"] = "com.example.app"
    }
}

dependencies {
    implementation("io.openback:openback-app-auth-android:1.0.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")   // lifecycleScope in the example
}
