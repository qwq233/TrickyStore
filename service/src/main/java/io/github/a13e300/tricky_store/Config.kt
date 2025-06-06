package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.ServiceManager
import com.akuleshov7.ktoml.Toml
import com.akuleshov7.ktoml.TomlIndentation
import com.akuleshov7.ktoml.TomlInputConfig
import com.akuleshov7.ktoml.TomlOutputConfig
import io.github.a13e300.tricky_store.keystore.CertHack
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import java.io.File

object Config {
    private val hackPackages = mutableSetOf<String>()
    private val generatePackages = mutableSetOf<String>()

    private fun updateTargetPackages(f: File?) = runCatching {
        hackPackages.clear()
        generatePackages.clear()
        listOf("com.google.android.gsf", "com.google.android.gms", "com.android.vending").forEach { generatePackages.add(it) }
        f?.readLines()?.forEach {
            if (it.isNotBlank() && !it.startsWith("#")) {
                val n = it.trim()
                if (n.endsWith("!")) generatePackages.add(n.removeSuffix("!").trim())
                else hackPackages.add(n)
            }
        }
        Logger.i("update hack packages: $hackPackages, generate packages=$generatePackages")
    }.onFailure {
        Logger.e("failed to update target files", it)
    }

    private fun updateKeyBox(f: File?) = runCatching {
        CertHack.readFromXml(f?.readText())
    }.onFailure {
        Logger.e("failed to update keybox", it)
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val SECURITY_PATCH_FILE = "security_patch.txt"
    private val root = File(CONFIG_PATH)

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            val f = when (event) {
                CLOSE_WRITE, MOVED_TO -> File(root, path)
                DELETE, MOVED_FROM -> null
                else -> return
            }
            when (path) {
                TARGET_FILE -> updateTargetPackages(f)
                KEYBOX_FILE -> updateKeyBox(f)
                SECURITY_PATCH_FILE -> parseDevConfig(f)
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        val scope = File(root, TARGET_FILE)
        if (scope.exists()) {
            updateTargetPackages(scope)
        } else {
            Logger.e("target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) {
            Logger.e("keybox file not found, please put it to $keybox !")
        } else {
            updateKeyBox(keybox)
        }

        val fDevConfig = File(root, SECURITY_PATCH_FILE)
        if (!fDevConfig.exists()) {
            fDevConfig.createNewFile()
            fDevConfig.writeText(Toml.encodeToString(devConfig))
        } else {
            parseDevConfig(fDevConfig)
        }

        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            iPm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"))
        }
        return iPm
    }

    fun needHack(callingUid: Int) = kotlin.runCatching {
        false
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    fun needGenerate(callingUid: Int) = kotlin.runCatching {
        if (generatePackages.isEmpty() && hackPackages.isEmpty()) return false
        val ps = getPm()?.getPackagesForUid(callingUid)
        ps?.any { it in generatePackages || it in hackPackages }
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    private val toml = Toml(
        inputConfig = TomlInputConfig(
            ignoreUnknownNames = false,
            allowEmptyValues = true,
            allowNullValues = true,
            allowEscapedQuotesInLiteralStrings = true,
            allowEmptyToml = true,
            ignoreDefaultValues = false,
        ),
        outputConfig = TomlOutputConfig(
            indentation = TomlIndentation.FOUR_SPACES,
        )
    )

    var devConfig = DeviceConfig()
        private set

    @Serializable
    data class DeviceConfig(
        val securityPatch: String = Build.VERSION.SECURITY_PATCH,
        val osVersion: Int = Build.VERSION.SDK_INT,
    )

    fun parseDevConfig(f: File?) = runCatching {
        f ?: return@runCatching
        if (!f.exists()) return@runCatching
        devConfig = toml.decodeFromString(DeviceConfig.serializer(), f.readText())
        // in case there're new updates for device config
        f.writeText(Toml.encodeToString(devConfig))
    }.onFailure {
        Logger.e("", it)
    }
}
