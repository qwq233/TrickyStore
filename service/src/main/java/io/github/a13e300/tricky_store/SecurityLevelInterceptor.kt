package io.github.a13e300.tricky_store

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.keystore.CertHack
import io.github.a13e300.tricky_store.keystore.Utils
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int
) : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val deleteKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "deleteKey")
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        private val importWrappedKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importWrappedKey")
        private val importKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")

        val keys = ConcurrentHashMap<Key, Info>()
        val keyPairs = ConcurrentHashMap<Key, Pair<KeyPair, List<Certificate>>>()

        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            keys[Key(uid, alias)]?.response
        fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? =
            keyPairs[Key(uid, alias)]
    }

    data class Key(val uid: Int, val alias: String)
    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        Logger.d("SecurityLevelInterceptor received onPreTransact code=$code uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
        if (!Config.needGenerate(callingUid)) return Skip
        if (code == generateKeyTransaction) {
            Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor =
                    data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                data.readInt()
                data.createByteArray()
                val kgp = CertHack.KeyGenParameters(params)
                // Logger.e("warn: attestation key not supported now")
                val pair = CertHack.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp)
                    ?: return@runCatching
                keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                val p = Parcel.obtain()
                p.writeNoException()
                p.writeTypedObject(response.metadata, 0)
                return OverrideReply(0, p)
            }.onFailure {
                Logger.e("parse key gen request", it)
            }
        } else if (code == importKeyTransaction) {
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)

                val keyDescriptor =
                    data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                data.readInt()
                val keyData = data.createByteArray() // pkcs8 format raw key bits

                val kgp = CertHack.KeyGenParameters(params)
                if (!kgp.purpose.any { it == 2 /* sign */ || it == 7 /* attest */ }) {
                    // we don't handle non-signing key request
                    Logger.i("only signing key request is supported now")
                    return Skip
                }


                val privateKey = if (kgp.algorithm == Algorithm.EC) {
                    KeyFactory.getInstance("EC").generatePrivate(
                        java.security.spec.PKCS8EncodedKeySpec(keyData)
                    )
                } else if (kgp.algorithm == Algorithm.RSA) {
                    KeyFactory.getInstance("RSA").generatePrivate(
                        java.security.spec.PKCS8EncodedKeySpec(keyData)
                    )
                } else {
                    Logger.e("unsupported algorithm ${kgp.algorithm}")
                    return Skip
                }

                Cache.preImportedKey(callingUid, callingPid, privateKey) {
                    val pair = CertHack.generateKeyPairWithImportedKey(keyDescriptor, kgp) {
                        val pair = Cache.getImportedKey(callingUid, callingPid) ?: return@generateKeyPairWithImportedKey null
                        Pair(pair.first.first, pair.second)
                    }
                    keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                    val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                    keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)

                    Logger.d("imported key generated uid=$callingUid alias=${keyDescriptor.alias}")
                }

                return Skip
            }.onFailure {
                Logger.e("", it)
            }
            return Skip
        }
        return Skip
    }

    private fun buildResponse(
        chain: List<Certificate>,
        params: CertHack.KeyGenParameters,
        descriptor: KeyDescriptor
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        Utils.putCertificateChain(metadata, chain.toTypedArray<Certificate>())
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        var a: Authorization
        for (i in params.purpose) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.PURPOSE
            a.keyParameter.value = KeyParameterValue.keyPurpose(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        for (i in params.digest) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.DIGEST
            a.keyParameter.value = KeyParameterValue.digest(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ALGORITHM
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.KEY_SIZE
        a.keyParameter.value = KeyParameterValue.integer(params.keySize)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.EC_CURVE
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED
        a.keyParameter.value = KeyParameterValue.boolValue(true) // TODO: copy
        a.securityLevel = level
        authorizations.add(a)
        // TODO: ORIGIN
        //OS_VERSION
        //OS_PATCHLEVEL
        //VENDOR_PATCHLEVEL
        //BOOT_PATCHLEVEL
        //CREATION_DATETIME
        //USER_ID
        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}
