import android.databinding.tool.ext.capitalizeUS
import org.jetbrains.kotlin.daemon.common.toHexString
import java.security.MessageDigest

plugins {
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlinx.serialization)
    alias(libs.plugins.agp.app)
}

val moduleId: String by rootProject.extra
val moduleName: String by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra
val author: String by rootProject.extra
val description: String by rootProject.extra

fun calculateChecksum(variantLowered: String): String {
    return MessageDigest.getInstance("SHA-256").run {
        update(moduleId.toByteArray(Charsets.UTF_8))
        update(moduleName.toByteArray(Charsets.UTF_8))
        update("$verName ($verCode-$commitHash-$variantLowered)".toByteArray(Charsets.UTF_8))
        update(verCode.toString().toByteArray(Charsets.UTF_8))
        update(author.toByteArray(Charsets.UTF_8))
        update(description.toByteArray(Charsets.UTF_8))
        digest().toHexString()
    }
}

android {
    namespace = "io.github.a13e300.tricky_store"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.a13e300.tricky_store"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        forEach {
            val checksum = calculateChecksum(it.name)
            it.buildConfigField("String", "CHECKSUM", "\"$checksum\"")
        }
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            signingConfig = signingConfigs["debug"]
        }
    }

    packaging {
        resources {
            excludes += "**"
        }
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = true
    }

    buildFeatures {
        aidl = true
        buildConfig = true
    }

}

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    compileOnly(libs.dev.rikka.hidden.stub)
    implementation(kotlin("reflect"))
    implementation(libs.ktoml.core)
    implementation(libs.ktoml.file)
    implementation(libs.bcpkix.jdk18on)
    implementation(libs.kotlinx.coroutines.android)
}

afterEvaluate {
    android.applicationVariants.forEach { variant ->
        val variantLowered = variant.name.lowercase()
        val variantCapped = variant.name.capitalizeUS()
        val pushTask = tasks.register<Task>("pushService$variantCapped") {
            group = "Service"
            dependsOn("assemble$variantCapped")
            doLast {
                providers.exec {
                    commandLine = listOf(
                        "adb",
                        "push",
                        layout.buildDirectory.file("outputs/apk/$variantLowered/service-$variantLowered.apk")
                            .get().asFile.absolutePath,
                        "/data/local/tmp/service.apk"
                    )
                }.standardOutput.asText.get()
                providers.exec {
                    commandLine = listOf(
                        "adb",
                        "shell",
                        "su -c 'rm /data/adb/modules/tricky_store/service.apk; mv /data/local/tmp/service.apk /data/adb/modules/tricky_store/'"
                    )
                }.standardOutput.asText.get()
            }
        }

        tasks.register<Task>("pushAndRestartService$variantCapped") {
            group = "Service"
            dependsOn(pushTask)
            doLast {
                providers.exec {
                    commandLine = listOf("adb", "shell", "su -c \"setprop ctl.restart keystore2\"")
                }.standardOutput.asText.get()
            }
        }
    }
}
