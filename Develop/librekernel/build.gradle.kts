import com.android.build.api.dsl.LibraryExtension

plugins {
    id("com.android.base")
    id("com.android.library")
}

configure<LibraryExtension> {
    namespace = "org.sakion.rekernel"

    defaultConfig {
        minSdk = 29
        lint.targetSdk = 36
        compileSdk = 36

        consumerProguardFiles("consumer-rules.pro")
    }


    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_25
        targetCompatibility = JavaVersion.VERSION_25
    }
}

dependencies {
    implementation("org.lsposed.hiddenapibypass:hiddenapibypass:6.1")
}
