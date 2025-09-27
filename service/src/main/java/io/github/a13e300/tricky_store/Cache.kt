package io.github.a13e300.tricky_store

import android.system.keystore2.KeyEntryResponse
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

object Cache {
    // imported key section
    data class Owner(val uid: Int, val pid: Int)

    // These imported keys will be naturally dropped when app exits and pid changes
    private val importedKeys = ConcurrentHashMap<Owner, Pair<Pair<PrivateKey, () -> Unit>, Certificate?>>()

    fun getImportedKey(uid: Int, pid: Int): Pair<Pair<PrivateKey, () -> Unit>, Certificate?>? =
        importedKeys[Owner(uid, pid)]

    fun preImportedKey(uid: Int, pid: Int, privateKey: PrivateKey, onFinish: () -> Unit) {
        importedKeys[Owner(uid, pid)] = Pair(Pair(privateKey, onFinish), null) as Pair<Pair<PrivateKey, () -> Unit>, Certificate?>
    }

    fun deleteImportedKey(uid: Int, pid: Int) = importedKeys.remove(Owner(uid, pid))

    fun finalizedImportedKey(uid: Int, pid: Int, cert: Certificate) {
        val pair = importedKeys[Owner(uid, pid)] ?: return
        importedKeys[Owner(uid, pid)] = Pair(pair.first, cert)
        // generate imported key
        pair.first.second.invoke()
    }

    // generated key section
    data class Key(val uid: Int, val alias: String)
    data class Info(val key: Key, val keyPair: KeyPair, val chain: List<Certificate>, val response: KeyEntryResponse)

    private val keys = ConcurrentHashMap<Key, Info>()

    fun putKey(uid: Int, alias: String, keyPair: KeyPair, chain: List<Certificate>, response: KeyEntryResponse) {
        keys[Key(uid, alias)] = Info(Key(uid, alias), keyPair, chain, response)
    }

    fun putKey(key: Key, info: Info) {
        keys[key] = info
    }

    fun getInfoByNspace(callingUid: Int, nspace: Long): List<Info> = keys.values.filter { it.key.uid == callingUid && it.response.metadata?.key?.nspace == nspace }

    fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? = keys[Key(uid, alias)]?.response

    fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? = keys[Key(uid, alias)]?.let { Pair(it.keyPair, it.chain) }

    fun deleteKey(uid: Int, alias: String) {
        keys.remove(Key(uid, alias))
    }

    fun deleteKey(key: Key) {
        keys.remove(key)
    }
}

