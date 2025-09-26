package io.github.a13e300.tricky_store

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.keystore.CertHack
import io.github.a13e300.tricky_store.keystore.Utils
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel, private val level: Int
) : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val deleteKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "deleteKey")
        private val createOperationTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        private val importWrappedKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importWrappedKey")
        private val importKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")

    }
    override fun onPreTransact(
        target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel
    ): Result {
        Logger.d("SecurityLevelInterceptor received onPreTransact code=$code uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
        if (!Config.needGenerate(callingUid)) return Skip
        when (code) {
            generateKeyTransaction -> runCatching {
                Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                data.readInt()
                data.createByteArray()
                val kgp = CertHack.KeyGenParameters(params)
                // Logger.e("warn: attestation key not supported now")
                val pair = CertHack.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp) ?: return@runCatching
                val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                Cache.putKey(callingUid, keyDescriptor.alias, pair.first, pair.second, response)
                val p = Parcel.obtain()
                p.writeNoException()
                p.writeTypedObject(response.metadata, 0)
                return OverrideReply(0, p)
            }.onFailure {
                Logger.e("parse key gen request", it)
            }


            importKeyTransaction -> runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)

                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
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
                    val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                    Cache.putKey(callingUid, keyDescriptor.alias, pair.first, pair.second, response)

                    Logger.d("imported key generated uid=$callingUid alias=${keyDescriptor.alias}")
                }

                return Skip
            }.onFailure {
                Logger.e("", it)
            }

            createOperationTransaction -> runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                Logger.d("createOperationTransaction uid=$callingUid pid=$callingPid")

                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip
                val params = data.createTypedArray(KeyParameter.CREATOR) ?: return Skip
                val kgp = CertHack.KeyGenParameters(params)

                val info = Cache.getInfoByNspace(keyDescriptor.nspace)
                if (info == null || (info.key.uid != callingUid)) {
                    Logger.e("key not found or uid mismatch")
                    return Skip
                }
                if (keyDescriptor.domain != 4) throw IllegalArgumentException("unsupported domain ${keyDescriptor.domain}")
                kgp.purpose.any { it != 2 /* sign */ && it != 7 /* attest */ } ||
                        throw IllegalArgumentException("unsupported purpose ${kgp.purpose}")
                kgp.digest.any { it != 4 } ||
                        throw IllegalArgumentException("unsupported digest ${kgp.digest}")
                val algorithm = when (kgp.algorithm) {
                    Algorithm.EC -> "SHA256withECDSA"
                    Algorithm.RSA -> "SHA256withRSA"
                    else -> throw IllegalArgumentException("unsupported algorithm ${kgp.algorithm}")
                }

                val op = KeyStoreOperation(info.keyPair.private, algorithm)
                val parcel = Parcel.obtain()
                parcel.writeNoException()
                val createOperationResponse = CreateOperationResponse().apply {
                    iOperation = op
                }
                parcel.writeTypedObject(createOperationResponse, 0)

                return OverrideReply(0, parcel)
            }.onFailure {
                Logger.e("", it)
            }
        }
        return Skip
    }

    private class KeyStoreOperation : IKeystoreOperation.Stub {
        val signature: Signature
        var isAborted = false

        constructor(privateKey: PrivateKey, algorithm: String) {
            signature = Signature.getInstance(algorithm)
            signature.initSign(privateKey)
        }

        override fun updateAad(aadInput: ByteArray?) {
            // do nothing for now
        }

        override fun update(input: ByteArray): ByteArray? {
            if (isAborted) throw IllegalStateException("operation aborted")
            signature.update(input)
            return null
        }

        override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
            if (isAborted) throw IllegalStateException("operation aborted")
            this.signature.update(input)
            return this.signature.sign()
        }

        override fun abort() {
            isAborted = true
        }
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
