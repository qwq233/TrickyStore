import com.android.build.gradle.AppExtension
import com.android.build.gradle.LibraryExtension
import java.io.ByteArrayOutputStream
import java.util.concurrent.ThreadLocalRandom

plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.jetbrains.kotlin.android) apply false
    alias(libs.plugins.android.library) apply false
}

fun String.execute(currentWorkingDir: File = file("./")): String {
    providers.exec {
        workingDir = currentWorkingDir
        commandLine = split("\\s".toRegex())
    }.standardOutput.asBytes.get().run {
        String(this).trim()
    }.run {
        return this
    }
}

val gitCommitCount = "git rev-list HEAD --count".execute().toInt()
val gitCommitHash = "git rev-parse --verify --short HEAD".execute()

// also the soname
val moduleId by extra("tricky_store")
val moduleName by extra("Tricky Store")
val author by extra("5ec1cff, James Clef")
val description by extra("A trick of keystore")
val verName by extra("v3.16")
val verCode by extra(gitCommitCount)
val commitHash by extra(gitCommitHash)
val abiList by extra(listOf("arm64-v8a", "x86_64"))

val androidMinSdkVersion by extra(29)
val androidTargetSdkVersion by extra(35)
val androidCompileSdkVersion by extra(35)
val androidBuildToolsVersion by extra("35.0.0")
val androidCompileNdkVersion by extra("28.1.13356709")
val androidSourceCompatibility by extra(JavaVersion.VERSION_17)
val androidTargetCompatibility by extra(JavaVersion.VERSION_17)

tasks.register("Delete", Delete::class) {
    delete(layout.buildDirectory)
}

fun Project.configureBaseExtension() {
    extensions.findByType(AppExtension::class)?.run {
        namespace = "io.github.a13e300.tricky_store"
        compileSdkVersion(androidCompileSdkVersion)
        ndkVersion = androidCompileNdkVersion
        buildToolsVersion = androidBuildToolsVersion

        defaultConfig {
            minSdk = androidMinSdkVersion
            targetSdk = androidCompileSdkVersion
            versionCode = verCode
            versionName = verName
        }

        compileOptions {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }

    extensions.findByType(LibraryExtension::class)?.run {
        namespace = "io.github.a13e300.tricky_store"
        compileSdk = androidCompileSdkVersion
        ndkVersion = androidCompileNdkVersion
        buildToolsVersion = androidBuildToolsVersion

        defaultConfig {
            minSdk = androidMinSdkVersion
        }

        lint {
            checkReleaseBuilds = false
            abortOnError = true
        }

        compileOptions {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }
}

subprojects {
    plugins.withId("com.android.application") {
        configureBaseExtension()
    }
    plugins.withId("com.android.library") {
        configureBaseExtension()
    }
    plugins.withType(JavaPlugin::class.java) {
        extensions.configure(JavaPluginExtension::class.java) {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }
}
