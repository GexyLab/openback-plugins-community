import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    `maven-publish`
}

group = "io.openback"
version = "1.0.0"

android {
    namespace = "io.openback.appauth.android"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
        aarMetadata {
            minCompileSdk = 34
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

dependencies {
    api("com.squareup.okhttp3:okhttp:4.12.0")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    api("androidx.activity:activity:1.9.3")
    implementation("androidx.browser:browser:1.8.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "io.openback"
            artifactId = "openback-app-auth-android"
            version = "1.0.0"
            afterEvaluate {
                from(components["release"])
            }
            pom {
                name.set("openback-app-auth-android")
                description.set("OpenBack App Auth for Android: sign-in to an OpenBack user pool (JSON API and hosted page with Custom Tabs + PKCE), Keystore-encrypted session, OkHttp interceptor.")
                url.set("https://github.com/GexyLab/openback-plugins-community/tree/main/SDK/Auth/android/1.0.0")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("gexylab")
                        name.set("GexyLab")
                    }
                }
                scm {
                    url.set("https://github.com/GexyLab/openback-plugins-community")
                    connection.set("scm:git:https://github.com/GexyLab/openback-plugins-community.git")
                    developerConnection.set("scm:git:ssh://git@github.com/GexyLab/openback-plugins-community.git")
                }
            }
        }
    }
}
