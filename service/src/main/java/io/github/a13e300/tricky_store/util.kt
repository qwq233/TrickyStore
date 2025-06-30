package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.ServiceManager
import android.os.SystemProperties
import android.telephony.TelephonyManager
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ThreadLocalRandom


fun getTransactCode(clazz: Class<*>, method: String) =
    clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }
        .getInt(null) // 2

val bootHash by lazy {
    getBootHashFromProp() ?: randomBytes()
}

// TODO: get verified boot keys
val bootKey by lazy {
    randomBytes()
}

@OptIn(ExperimentalStdlibApi::class)
fun getBootHashFromProp(): ByteArray? {
    val b = SystemProperties.get("ro.boot.vbmeta.digest", null) ?: return null
    if (b.length != 64) return null
    return b.hexToByteArray()
}

fun randomBytes() = ByteArray(32).also { ThreadLocalRandom.current().nextBytes(it) }

// Data class for security_patch.txt
private data class CustomPatchLevel(
    val system: String? = null,
    val vendor: String? = null,
    val boot: String? = null,
    val all: String? = null
)

private val customPatchLevel: CustomPatchLevel? by lazy {
    val file = File("/data/adb/tricky_store/security_patch.txt")
    if (!file.exists()) return@lazy null
    val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
    if (lines.isEmpty()) return@lazy null
    // Simple mode: first line is a patch level
    if (lines.size == 1 && !lines[0].contains("=")) {
        return@lazy CustomPatchLevel(all = lines[0])
    }
    // Advanced mode: parse key=value pairs
    val map = mutableMapOf<String, String>()
    for (line in lines) {
        val idx = line.indexOf('=')
        if (idx > 0) {
            val key = line.substring(0, idx).trim().lowercase()
            val value = line.substring(idx + 1).trim()
            map[key] = value
        }
    }
    // If all is set, use it as default for system, vendor, boot if not set
    val all = map["all"]
    CustomPatchLevel(
        system = map["system"] ?: all,
        vendor = map["vendor"] ?: all,
        boot = map["boot"] ?: all,
        all = all
    )
}

private fun getCustomPatchLevel(key: String, long: Boolean): Int? {
    val cpl = customPatchLevel ?: return null
    val value = when (key) {
        "system" -> cpl.system ?: cpl.all
        "vendor" -> cpl.vendor ?: cpl.all
        "boot" -> cpl.boot ?: cpl.all
        else -> cpl.all
    } ?: return null
    if (value.equals("no", ignoreCase = true)) return null
    if (value.equals("prop", ignoreCase = true)) return null
    // Accept both 20250301 and 2025-03-01
    val normalized = value.replace("-", "")
    return try {
        if (long) {
            if (normalized.length == 8) normalized.substring(0, 4).toInt() * 10000 + normalized.substring(4, 6).toInt() * 100 + normalized.substring(6, 8).toInt()
            else if (normalized.length == 6) normalized.substring(0, 4).toInt() * 10000 + normalized.substring(4, 6).toInt() * 100
            else null
        } else {
            if (normalized.length == 8) normalized.substring(0, 4).toInt() * 100 + normalized.substring(4, 6).toInt()
            else if (normalized.length == 6) normalized.substring(0, 4).toInt() * 100 + normalized.substring(4, 6).toInt()
            else null
        }
    } catch (_: Exception) {
        null
    }
}

// Fallback to devconfig.toml if security_patch.txt fails
val patchLevel
    get() = getCustomPatchLevel("system", false)
        ?: runCatching { Config.devConfig.securityPatch.convertPatchLevel(false) }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(false))

val patchLevelLong
    get() = getCustomPatchLevel("system", true)
        ?: runCatching { Config.devConfig.securityPatch.convertPatchLevel(true) }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(false))

val vendorPatchLevel: Int
    get() = getCustomPatchLevel("vendor", false)
        ?: runCatching { Config.devConfig.securityPatch.convertPatchLevel(false) }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(false))

val vendorPatchLevelLong: Int
    get() = getCustomPatchLevel("vendor", true)
        ?: runCatching { Config.devConfig.securityPatch.convertPatchLevel(true) }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(true))

val bootPatchLevel: Int
    get() = getCustomPatchLevel("boot", false)
        ?: runCatching { Config.devConfig.securityPatch.convertPatchLevel(false) }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(false))

val bootPatchLevelLong: Int
    get() = getCustomPatchLevel("boot", true)
        ?: runCatching { Config.devConfig.securityPatch.convertPatchLevel(true) }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(true))

val osVersion
    get() = Config.devConfig.osVersion.run {
        if (this > 0) return@run getOsVersion(this)
        else return@run getOsVersion(Build.VERSION.SDK_INT)
    }

private fun getOsVersion(num: Int) = when (num) {
    Build.VERSION_CODES.VANILLA_ICE_CREAM -> 150000
    Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> 140000
    Build.VERSION_CODES.TIRAMISU -> 130000
    Build.VERSION_CODES.S_V2 -> 120100
    Build.VERSION_CODES.S -> 120000
    // i don't know whether rest of these are correct actually, so PR if anything is wrong.
    Build.VERSION_CODES.Q -> 110000
    else -> 150000
}

fun String.convertPatchLevel(long: Boolean) = runCatching {
    val l = split("-")
    if (long) l[0].toInt() * 10000 + l[1].toInt() * 100 + l[2].toInt()
    else l[0].toInt() * 100 + l[1].toInt()
}.onFailure { Logger.e("invalid patch level $this !", it) }.getOrDefault(202404)

fun IPackageManager.getPackageInfoCompat(name: String, flags: Long, userId: Int) =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getPackageInfo(name, flags, userId)
    } else {
        getPackageInfo(name, flags.toInt(), userId)
    }

val apexInfos by lazy {
    mutableListOf<Pair<String, Long>>().also { list ->
        IPackageManager.Stub.asInterface(ServiceManager.getService("package")).run {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                getInstalledPackages(PackageManager.MATCH_APEX.toLong(), 0)
            } else {
                getInstalledPackages(PackageManager.MATCH_APEX, 0)
            }.list.forEach {
                list.add(it.packageName to it.longVersionCode)
            }
        }
    }.sortedBy { it.first }.toList() // soft to ensure it complies with AOSP requirements (lexicographically)
}

val moduleHash: ByteArray by lazy {
    mutableListOf<ASN1Encodable>().apply {
        apexInfos.forEach {
            add(DEROctetString(it.first.toByteArray()))
            add(ASN1Integer(it.second))
        }
    }.toTypedArray().run {
        DERSequence(this)
    }.encoded.run {
        MessageDigest.getInstance("SHA-256").also { it.update(this) }.digest()
    }
}

@Suppress("MissingPermission")
val telephonyInfos by lazy {
    mutableListOf<DERTaggedObject>().apply {
        add(DERTaggedObject(true, 714, (DEROctetString(SystemProperties.get("ro.ril.oem.imei", null)?.toByteArray()))))
        add(DERTaggedObject(true, 715, DEROctetString(SystemProperties.get("ro.ril.oem.meid", null)?.toByteArray())))
        add(DERTaggedObject(true, 723, DEROctetString(SystemProperties.get("ro.ril.oem.imei2", null)?.toByteArray())))
        add(DERTaggedObject(true, 713, DEROctetString(SystemProperties.get("ro.serialno", null)?.toByteArray())))
    }.toList()
}

fun String.trimLine() = trim().split("\n").joinToString("\n") { it.trim() }
