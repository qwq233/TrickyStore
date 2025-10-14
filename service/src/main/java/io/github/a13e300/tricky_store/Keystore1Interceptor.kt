package io.github.a13e300.tricky_store

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import android.security.Credentials
import android.security.KeyStore
import android.security.keymaster.ExportResult
import android.security.keymaster.KeyCharacteristics
import android.security.keymaster.KeymasterArguments
import android.security.keymaster.KeymasterCertificateChain
import android.security.keymaster.KeymasterDefs
import android.security.keystore.IKeystoreCertificateChainCallback
import android.security.keystore.IKeystoreExportKeyCallback
import android.security.keystore.IKeystoreKeyCharacteristicsCallback
import android.security.keystore.IKeystoreService
import android.security.keystore.KeystoreResponse
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.keystore.CertHack
import top.qwq2333.ohmykeymint.CallerInfo
import java.math.BigInteger
import java.security.KeyPair
import java.util.Date
import kotlin.system.exitProcess

@SuppressLint("BlockedPrivateApi")
object Keystore1Interceptor : BinderInterceptor() {
    private val getTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "get")
    private val generateKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "generateKey")
    private val getKeyCharacteristicsTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getKeyCharacteristics")
    private val exportKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "exportKey")
    private val attestKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "attestKey")
    private lateinit var keystore: IBinder

    private const val DESCRIPTOR = "android.security.keystore.IKeystoreService"

    private val KeyArguments = HashMap<Key, CertHack.KeyGenParameters>()
    private val KeyPairs = HashMap<Key, KeyPair>()

    data class Key(val uid: Int, val alias: String)

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        ctx: CallerInfo,
        data: Parcel
    ): Result {
        val callingUid = ctx.callingUid.toInt()
        ctx.callingPid.toInt()
        if (CertHack.canHack()) {
            if (code == getTransaction) {
                if (Config.needHack(callingUid)) {
                    return Continue
                } else if (Config.needGenerate(callingUid)) {
                    //needn't intercept getTransaction pre because it was stored in keystore
                    return Skip
                }
            } else if (Config.needGenerate(callingUid)) {
                when (code) {
                    generateKeyTransaction -> {
                        kotlin.runCatching {
                            data.enforceInterface(DESCRIPTOR)
                            val callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder())
                            val alias = data.readString()!!.split("_")[1]
                            Logger.i("generateKeyTransaction uid $callingUid alias $alias")
                            val check = data.readInt()
                            val kma = KeymasterArguments()
                            val kgp = CertHack.KeyGenParameters()
                            if (check == 1) {
                                kma.readFromParcel(data)
                                kgp.algorithm = kma.getEnum(KeymasterDefs.KM_TAG_ALGORITHM, 0)
                                kgp.keySize = kma.getUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 0).toInt()
                                kgp.setEcCurveName(kgp.keySize)
                                kgp.purpose = kma.getEnums(KeymasterDefs.KM_TAG_PURPOSE)
                                kgp.digest = kma.getEnums(KeymasterDefs.KM_TAG_DIGEST)
                                kgp.certificateNotBefore = kma.getDate(KeymasterDefs.KM_TAG_ACTIVE_DATETIME, Date())
                                if (kgp.algorithm == KeymasterDefs.KM_ALGORITHM_RSA) {
                                    try {
                                        val getArgumentByTag = KeymasterArguments::class.java.getDeclaredMethods().first { it.name == "getArgumentByTag" }
                                        getArgumentByTag.isAccessible = true
                                        val rsaArgument = getArgumentByTag.invoke(kma, KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT)

                                        val getLongTagValue = KeymasterArguments::class.java.getDeclaredMethods().first { it.name == "getLongTagValue" }
                                        getLongTagValue.isAccessible = true
                                        kgp.rsaPublicExponent = getLongTagValue.invoke(kma, rsaArgument) as BigInteger
                                    } catch (ex: Exception) {
                                        Logger.e("Read rsaPublicExponent error", ex)
                                    }
                                }
                                KeyArguments[Key(callingUid, alias)] = kgp
                            }

                            val kc = KeyCharacteristics()
                            kc.swEnforced = KeymasterArguments()
                            kc.hwEnforced = kma

                            val ksrP = Parcel.obtain()
                            ksrP.writeInt(KeyStore.NO_ERROR)
                            ksrP.writeString("")
                            ksrP.setDataPosition(0)
                            val ksr = KeystoreResponse.CREATOR.createFromParcel(ksrP)
                            ksrP.recycle()
                            callback.onFinished(ksr, kc)

                            val p = Parcel.obtain()
                            p.writeNoException()
                            p.writeInt(KeyStore.NO_ERROR)
                            return OverrideReply(0, p)
                        }.onFailure {
                            Logger.e("generateKeyTransaction error", it)
                        }
                    }

                    getKeyCharacteristicsTransaction -> {
                        kotlin.runCatching {
                            data.enforceInterface(DESCRIPTOR)
                            val callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder())
                            val alias = data.readString()!!.split("_")[1]
                            Logger.i("getKeyCharacteristicsTransaction uid $callingUid alias $alias")
                            val kc = KeyCharacteristics()
                            val kma = KeymasterArguments()
                            kma.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, KeyArguments[Key(callingUid, alias)]!!.algorithm)
                            kc.swEnforced = KeymasterArguments()
                            kc.hwEnforced = kma

                            val ksrP = Parcel.obtain()
                            ksrP.writeInt(KeyStore.NO_ERROR)
                            ksrP.writeString("")
                            ksrP.setDataPosition(0)
                            val ksr = KeystoreResponse.CREATOR.createFromParcel(ksrP)
                            ksrP.recycle()

                            callback.onFinished(ksr, kc)

                            val p = Parcel.obtain()
                            p.writeNoException()
                            p.writeInt(KeyStore.NO_ERROR)
                            return OverrideReply(0, p)
                        }.onFailure {
                            Logger.e("getKeyCharacteristicsTransaction error", it)
                        }
                    }

                    exportKeyTransaction -> {
                        kotlin.runCatching {
                            data.enforceInterface(DESCRIPTOR)
                            val callback = IKeystoreExportKeyCallback.Stub.asInterface(data.readStrongBinder())
                            val alias = data.readString()!!.split("_")[1]
                            Logger.i("exportKeyTransaction uid $callingUid alias $alias")
                            val kp = CertHack.generateKeyPair(KeyArguments[Key(callingUid, alias)]!!)
                            KeyPairs[Key(callingUid, alias)] = kp!!

                            val erP = Parcel.obtain()
                            erP.writeInt(KeyStore.NO_ERROR)
                            erP.writeByteArray(kp.public.encoded)
                            erP.setDataPosition(0)
                            val er = ExportResult.CREATOR.createFromParcel(erP)
                            erP.recycle()

                            callback.onFinished(er)

                            val p = Parcel.obtain()
                            p.writeNoException()
                            p.writeInt(KeyStore.NO_ERROR)
                            return OverrideReply(0, p)
                        }.onFailure {
                            Logger.e("exportKeyTransaction error", it)
                        }
                    }

                    attestKeyTransaction -> {
                        kotlin.runCatching {
                            data.enforceInterface(DESCRIPTOR)
                            val callback = IKeystoreCertificateChainCallback.Stub.asInterface(data.readStrongBinder())
                            val alias = data.readString()!!.split("_")[1]
                            Logger.i("attestKeyTransaction uid $callingUid alias $alias")
                            val check = data.readInt()
                            val kma = KeymasterArguments()
                            if (check == 1) {
                                kma.readFromParcel(data)
                                val attestationChallenge = kma.getBytes(KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, ByteArray(0))

                                val ksrP = Parcel.obtain()
                                ksrP.writeInt(KeyStore.NO_ERROR)
                                ksrP.writeString("")
                                ksrP.setDataPosition(0)
                                val ksr = KeystoreResponse.CREATOR.createFromParcel(ksrP)
                                ksrP.recycle()

                                val key = Key(callingUid, alias)
                                val ka = KeyArguments[key]!!
                                ka.attestationChallenge = attestationChallenge
                                val chain = CertHack.generateChain(callingUid, ka, KeyPairs[key]!!)

                                val kcc = KeymasterCertificateChain(chain)
                                callback.onFinished(ksr, kcc)
                            }

                            val p = Parcel.obtain()
                            p.writeNoException()
                            p.writeInt(KeyStore.NO_ERROR)
                            return OverrideReply(0, p)
                        }.onFailure {
                            Logger.e("attestKeyTransaction error", it)
                        }
                    }
                }
            }
        }
        return Skip
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        ctx: CallerInfo,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        val callingUid = ctx.callingUid.toInt()
        val callingPid = ctx.callingPid.toInt()
        if (target != keystore || code != getTransaction || reply == null) return Skip
        if (kotlin.runCatching { reply.readException() }.exceptionOrNull() != null) return Skip
        val p = Parcel.obtain()
        Logger.d("intercept post $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()} replySz=${reply.dataSize()}")
        try {
            data.enforceInterface(DESCRIPTOR)
            val alias = data.readString() ?: ""
            var response = reply.createByteArray()
            if (alias.startsWith(Credentials.USER_CERTIFICATE)) {
                response = CertHack.hackCertificateChainUSR(response!!, alias.split("_")[1], callingUid)
                Logger.i("hacked leaf of uid=$callingUid")
                p.writeNoException()
                p.writeByteArray(response)
                return OverrideReply(0, p)
            } else if (alias.startsWith(Credentials.CA_CERTIFICATE)) {
                response = CertHack.hackCertificateChainCA(response!!, alias.split("_")[1], callingUid)
                Logger.i("hacked caList of uid=$callingUid")
                p.writeNoException()
                p.writeByteArray(response)
                return OverrideReply(0, p)
            } else p.recycle()
        } catch (t: Throwable) {
            Logger.e("failed to hack certificate chain of uid=$callingUid pid=$callingPid!", t)
            p.recycle()
        }
        return Skip
    }

    private var triedCount = 0
    private var injected = false

    fun tryRunKeystoreInterceptor(): Boolean {
        Logger.i("trying to register keystore interceptor ($triedCount) ...")
        val b = ServiceManager.getService("android.security.keystore") ?: return false
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
                        "exec ./inject `pidof keystore` libtricky_store.so entry"
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
        keystore = b
        Logger.i("register for Keystore $keystore!")
        registerBinderInterceptor(bd, b, this)
        keystore.linkToDeath(Killer, 0)
        return true
    }

    object Killer : IBinder.DeathRecipient {
        override fun binderDied() {
            Logger.d("keystore exit, daemon restart")
            exitProcess(0)
        }
    }
}