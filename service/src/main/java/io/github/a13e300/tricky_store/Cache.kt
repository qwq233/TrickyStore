package io.github.a13e300.tricky_store

import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

object Cache {
    data class Owner(val uid: Int, val pid: Int)

    // These imported keys will be naturally dropped when app exits and pid changes
    private val importedKeys = ConcurrentHashMap<Owner, Pair<Pair<PrivateKey, () -> Unit>, Certificate?>>()

    fun getImportedKey(uid: Int, pid: Int): Pair<Pair<PrivateKey, () -> Unit>, Certificate?>? =
        importedKeys[Owner(uid, pid)]

    fun preImportedKey(uid: Int, pid: Int, privateKey: PrivateKey, onFinish: () -> Unit) {
        importedKeys[Owner(uid, pid)] = Pair(Pair(privateKey, onFinish), null) as Pair<Pair<PrivateKey, () -> Unit>, Certificate?>
    }

    fun finalizedImportedKey(uid: Int, pid: Int, cert: Certificate) {
        val pair = importedKeys[Owner(uid, pid)] ?: return
        importedKeys[Owner(uid, pid)] = Pair(pair.first, cert)
        // generate imported key
        pair.first.second.invoke()
    }
}

