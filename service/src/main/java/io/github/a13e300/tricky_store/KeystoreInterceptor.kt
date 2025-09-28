package io.github.a13e300.tricky_store

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import io.github.a13e300.tricky_store.Cache.Key
import io.github.a13e300.tricky_store.Config.devConfig
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.keystore.CertHack
import io.github.a13e300.tricky_store.keystore.Utils
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
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (!Config.needGenerate(callingUid)) return Skip
        Logger.d("KeystoreInceptor onPreTransact code=$code")
        when (code) {
            getKeyEntryTransaction -> {
                Logger.d("KeystoreInceptor getKeyEntryTransaction pre $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
                if (CertHack.canHack()) {
                    if (Config.needGenerate(callingUid))
                        runCatching {
                            data.enforceInterface(IKeystoreService.DESCRIPTOR)
                            if (!devConfig.globalConfig.generateKey
                                || devConfig.additionalAppConfig[callingUid.getPackageNameByUid()]?.generateKey == false
                            ) {
                                Logger.d("generateKey feature disabled for $callingUid")
                                return Skip
                            }

                            val descriptor =
                                data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                            val response =
                                Cache.getKeyResponse(callingUid, descriptor.alias)
                            val p = Parcel.obtain()
                            if (response == null) {
                                p.writeTypedObject(null, 0)
                            } else {
                                Logger.i("generate key for uid=$callingUid alias=${descriptor.alias}")
                                p.writeNoException()
                                p.writeTypedObject(response, 0)
                            }
                            return OverrideReply(0, p)
                        }
                    else if (Config.needHack(callingUid)) return Continue
                    return Skip
                }
            }

            updateSubcomponentTransaction -> {
                Logger.d("KeystoreInceptor onPreTransact updateSubcomponent uid=$callingUid pid=$callingPid")
                runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    if (!devConfig.globalConfig.importKey
                        || devConfig.additionalAppConfig[callingUid.getPackageNameByUid()]?.importKey == false
                    ) {
                        Logger.d("importKey feature disabled for $callingUid")
                        return Skip
                    }
                    val descriptor =
                        data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                    val publicCert = data.createByteArray()
                    val certificateChain = data.createByteArray()

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
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                if (keyDescriptor == null) return Skip

                Logger.d("KeystoreInterceptor deleteKey uid=$callingUid alias=${keyDescriptor.alias}")

                Cache.deleteKey(Key(callingUid, keyDescriptor.alias))
                Cache.deleteImportedKey(callingUid, callingPid)

                return Skip
            }
        }
        return Skip
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        if (target != keystore || reply == null) return Skip
        if (kotlin.runCatching { reply.readException() }.exceptionOrNull() != null) return Skip
        val p = Parcel.obtain()
        Logger.d("intercept post $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()} replySz=${reply.dataSize()}")

        if (code == deleteKeyTransaction && resultCode == 0) {
            data.enforceInterface("android.system.keystore2.IKeystoreService")
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            if (keyDescriptor == null || keyDescriptor.domain == 0) return Skip

            Logger.d("KeystoreInterceptor deleteKey uid=$callingUid alias=${keyDescriptor.alias}")

            Cache.deleteKey(Key(callingUid, keyDescriptor.alias))
            Cache.deleteImportedKey(callingUid, callingPid)

            return Skip
        } else if (code == getKeyEntryTransaction) {
            Logger.d("KeystoreInterceptor intercept getKeyEntry uid=$callingUid pid=$callingPid")
            try {
                data.enforceInterface("android.system.keystore2.IKeystoreService")
                if (!devConfig.globalConfig.generateKey
                    || devConfig.additionalAppConfig[callingUid.getPackageNameByUid()]?.generateKey == false
                ) {
                    Logger.d("getKeyEntry feature disabled for $callingUid")
                    return Skip
                }
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)
                val chain = Utils.getCertificateChain(response)
                if (chain != null) {
                    val newChain = CertHack.hackCertificateChain(chain)
                    Utils.putCertificateChain(response, newChain)
                    Logger.i("hacked cert of uid=$callingUid")
                    p.writeNoException()
                    p.writeTypedObject(response, 0)
                    return OverrideReply(0, p)
                } else {
                    p.recycle()
                }
            } catch (t: Throwable) {
                Logger.e("failed to hack certificate chain of uid=$callingUid pid=$callingPid!", t)
                p.recycle()
            }
        } else if (code == updateSubcomponentTransaction) {
            Logger.d("onPostTransact updateSubcomponent uid=$callingUid pid=$callingPid")
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
