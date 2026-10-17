plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "net.imohsen7.l2tpvpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.imohsen7.l2tpvpn"
        minSdk = 24
        targetSdk = 32
        versionCode = 1
        versionName = "0.1.0-test"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
    buildTypes {
        debug { isMinifyEnabled = false }
        release {
            isMinifyEnabled = false
            // Release APK must be signed by a key managed by the owner.
        }
    }
}


dependencies {
    testImplementation("junit:junit:4.13.2")
}
