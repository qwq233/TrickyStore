package io.github.a13e300.tricky_store

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import android.os.ServiceSpecificException
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.ResponseCode
import io.github.a13e300.tricky_store.Cache.Key
import io.github.a13e300.tricky_store.Config.getOmk
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import top.qwq2333.ohmykeymint.CallerInfo
import java.security.cert.CertificateFactory
import kotlin.system.exitProcess

@SuppressLint("BlockedPrivateApi")
object KeystoreInterceptor : BinderInterceptor() {
    private val getSecurityLevelTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getSecurityLevel") // 1
    private val getKeyEntryTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry") // 2
    private val updateSubcomponentTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "updateSubcomponent") // 3
    private val deleteKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "deleteKey") // 5

    private lateinit var keystore: IBinder

    private var teeInterceptor: SecurityLevelInterceptor? = null
    private var strongBoxInterceptor: SecurityLevelInterceptor? = null

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        ctx: CallerInfo,
        data: Parcel
    ): Result {
        val callingUid = ctx.callingUid.toInt()
        val callingPid = ctx.callingPid.toInt()
        if (!Config.needGenerate(callingUid)) return Skip
        val omk = getOmk()
        Logger.d("KeystoreInceptor onPreTransact code=$code")
        when (code) {
            getSecurityLevelTransaction -> {
                omk ?: return Skip

                val level = data.readInt()

                Parcel.obtain().apply {
                    writeNoException()
                    writeStrongBinder(omk.getSecurityLevel(level).asBinder())
                }.run {
                    return OverrideReply(0, this)
                }
            }
            getKeyEntryTransaction -> {
                Logger.d("KeystoreInceptor getKeyEntryTransaction pre $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
                if (Config.needGenerate(callingUid))
                    runCatching {
                        data.enforceInterface(IKeystoreService.DESCRIPTOR)
                        if (!Config.isGenerateKeyEnabled(callingUid)) {
                            Logger.d("generateKey feature disabled for $callingUid")
                            return Skip
                        }

                        val descriptor =
                            data.readTypedObject(KeyDescriptor.CREATOR)

                        if (descriptor == null) {
                            Logger.d("descriptor is null, skipping")
                            return Skip
                        }

                        val response = if (omk != null) {
                            omk.getKeyEntry(ctx, descriptor)
                        } else {
                            Cache.getKeyResponse(callingUid, descriptor.alias)
                        }

                        val p = Parcel.obtain()
                        if (response != null) {
                            Logger.i("generate key for uid=$callingUid alias=${descriptor.alias}")
                            p.writeNoException()
                            p.writeTypedObject(response, 0)
                        } else {
                            Logger.d("key not found for uid=$callingUid alias=${descriptor.alias}")
                            p.writeException(
                                ServiceSpecificException(
                                    ResponseCode.KEY_NOT_FOUND,
                                    "key not found for uid=$callingUid alias=${descriptor.alias}"
                                )
                            )
                        }

                        return OverrideReply(0, p)
                    }.onFailure {
                        Logger.e("", it)
                    }
            }

            updateSubcomponentTransaction -> {
                Logger.d("KeystoreInceptor onPreTransact updateSubcomponent uid=$callingUid pid=$callingPid")
                runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    if (!Config.isImportKeyEnabled(callingUid)) {
                        Logger.d("importKey feature disabled for $callingUid")
                        return Skip
                    }
                    val descriptor =
                        data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                    val publicCert = data.createByteArray()
                    val certificateChain = data.createByteArray()

                    if (omk != null) {
                        omk.updateSubcomponent(
                            ctx,
                            descriptor,
                            publicCert,
                            certificateChain
                        )

                        Parcel.obtain().apply {
                            writeNoException()
                        }.run {
                            return OverrideReply(0, this)
                        }
                    }

                    if (certificateChain != null) {
                        Logger.d("updateSubcomponent certificateChain sz=${certificateChain.size}")
                    }

                    if (publicCert != null) {
                        val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
                        val cert = cf.generateCertificate(publicCert.inputStream())

                        Logger.d("$cert")

                        Cache.finalizedImportedKey(callingUid, callingPid, cert)
                        Logger.i("store public cert uid=$callingUid alias=${descriptor.alias} sz=${publicCert.size}")
                    }
                }.onFailure {
                    Logger.e("failed to read updateSubcomponent data", it)
                }
            }

            deleteKeyTransaction -> {
                Logger.d("KeystoreInceptor onPreTransact deleteKeyTransaction uid=$callingUid pid=$callingPid")
                data.enforceInterface("android.system.keystore2.IKeystoreService")
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip

                if (omk != null) {
                    omk.deleteKey(ctx, keyDescriptor)

                    Parcel.obtain().apply {
                        writeNoException()
                    }.run {
                        return OverrideReply(0, this)
                    }
                }

                Logger.d("KeystoreInterceptor deleteKey uid=$callingUid alias=${keyDescriptor.alias}")

                Cache.deleteKey(Key(callingUid, keyDescriptor.alias))
                Cache.deleteImportedKey(callingUid, callingPid)

                return Skip
            }
        }
        return Skip
    }

    private var triedCount = 0
    private var injected = false

    fun tryRunKeystoreInterceptor(): Boolean {
        Logger.i("trying to register keystore interceptor ($triedCount) ...")
        val b = ServiceManager.getService("android.system.keystore2.IKeystoreService/default") ?: return false
        val bd = getBinderBackdoor(b)
        if (bd == null) {
            // no binder hook, try inject
            if (triedCount >= 3) {
                Logger.e("tried injection but still has no backdoor, exit")
                exitProcess(1)
            }
            if (!injected) {
                Logger.i("trying to inject keystore ...")
                val p = Runtime.getRuntime().exec(
                    arrayOf(
                        "/system/bin/sh",
                        "-c",
                        "exec ./inject `pidof keystore2` libtricky_store.so entry"
                    )
                )
                // logD(p.inputStream.readBytes().decodeToString())
                // logD(p.errorStream.readBytes().decodeToString())
                if (p.waitFor() != 0) {
                    Logger.e("failed to inject! daemon exit")
                    exitProcess(1)
                }
                injected = true
            }
            triedCount += 1
            return false
        }
        val ks = IKeystoreService.Stub.asInterface(b)
        val tee = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT) }
            .getOrNull()
        val strongBox =
            kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.STRONGBOX) }.getOrNull()
        keystore = b
        Logger.i("register for Keystore $keystore!")
        registerBinderInterceptor(bd, b, this)
        keystore.linkToDeath(Killer, 0)
        if (tee != null) {
            Logger.i("register for TEE SecurityLevel $tee!")
            val interceptor = SecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
            registerBinderInterceptor(bd, tee.asBinder(), interceptor)
            teeInterceptor = interceptor
        } else {
            Logger.i("no TEE SecurityLevel found!")
        }
        if (strongBox != null) {
            Logger.i("register for StrongBox SecurityLevel $tee!")
            val interceptor = SecurityLevelInterceptor(strongBox, SecurityLevel.STRONGBOX)
            registerBinderInterceptor(bd, strongBox.asBinder(), interceptor)
            strongBoxInterceptor = interceptor
        } else {
            Logger.i("no StrongBox SecurityLevel found!")
        }
        return true
    }

    object Killer : IBinder.DeathRecipient {
        override fun binderDied() {
            Logger.d("keystore exit, daemon restart")
            exitProcess(0)
        }
    }
}
