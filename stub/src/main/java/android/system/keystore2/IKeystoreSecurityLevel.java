package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * {@code IKeystoreSecurityLevel} is the per backend interface to Keystore. It provides
 * access to all requests that require KeyMint interaction, such as key import
 * and generation, as well as cryptographic operations.
 *
 * <h2>Error conditions</h2>
 * Error conditions are reported as service specific error.
 * Positive codes correspond to {@link android.system.keystore2.ResponseCode}
 * and indicate error conditions diagnosed by the Keystore 2.0 service.
 * Negative codes correspond to {@link android.hardware.security.keymint.ErrorCode} and
 * indicate KeyMint back end errors. Refer to the KeyMint interface spec for
 * detail.
 */
public interface IKeystoreSecurityLevel extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreSecurityLevel";

    /**
     * This flag disables cryptographic binding to the LSKF for auth bound keys.
     * It has no effect non auth bound keys. Such keys are not bound to the LSKF by
     * default.
     */
    int KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING = 0x1;

    /**
     * This function creates a new key operation. Operations are the mechanism by which the
     * secret or private key material of a key can be used. There is a limited number
     * of operation slots. Implementations may prune an existing operation to make room
     * for a new one. The pruning strategy is implementation defined, but it must
     * account for forced operations (see parameter {@code forced} below).
     * Forced operations require the caller to possess the {@code REQ_FORCED_OP} permission.
     *
     * <h2>Pruning strategy recommendation</h2>
     * It is recommended to choose a strategy that rewards "good" behavior.
     * It is considered good behavior not to hog operations. Clients that use
     * few parallel operations shall have a better chance of starting and finishing
     * an operations than those that use many. Clients that use frequently update their
     * operations shall have a better chance to complete them successfully that those
     * that let their operations linger.
     *
     * <h2>Error conditions</h2>
     * {@link ResponseCode#BACKEND_BUSY} if the implementation was unable to find a free
     * or free up an operation slot for the new operation.
     *
     * @param key                 Describes the key that is to be used for the operation.
     * @param operationParameters Additional operation parameters that describe the nature
     *                            of the requested operation.
     * @param forced              A forced operation has a very high pruning power. The implementation may
     *                            select an operation to be pruned that would not have been pruned otherwise to
     *                            free up an operation slot for the caller. Also, the resulting operation shall
     *                            have a very high pruning resistance and cannot be pruned even by other forced
     *                            operations.
     * @return The operation interface which also acts as a handle to the pending
     * operation and an optional operation challenge wrapped into the
     * {@code CreateOperationResponse} parcelable. If the latter is present, user
     * authorization is required for this operation.
     * @throws RemoteException if the remote operation fails
     */
    CreateOperationResponse createOperation(@NonNull KeyDescriptor key,
                                            @NonNull KeyParameter[] operationParameters,
                                            boolean forced) throws RemoteException;

    /**
     * Generates a new key and associates it with the given descriptor.
     *
     * <h2>Error conditions</h2>
     * {@link ResponseCode#INVALID_ARGUMENT} if {@code key.domain} is set to any other value than
     * the ones described above.
     * A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     *
     * @param key            The domain field of the key descriptor governs how the key will be stored.
     *                       <ul>
     *                       <li>App: The key is stored by the given alias string in the implicit UID namespace
     *                              of the caller.</li>
     *                       <li>SeLinux: The key is stored by the alias string in the namespace given by the
     *                                  {@code nspace} field provided the caller has the appropriate access rights.</li>
     *                       <li>Blob: The key is returned as an opaque KeyMint blob in the KeyMetadata.key.blob
     *                               field of the return value.
     *                               The {@code alias} field is ignored. The caller must have the {@code MANAGE_BLOB}
     *                               permission for the targeted {@code keystore2_key} context given by
     *                               {@code nspace}. {@code nspace} is translated into the corresponding target context
     *                               {@code <target_context>} and {@code <target_context>:keystore2_key manage_blob} is
     *                               checked against the caller's context.</li>
     *                       </ul>
     * @param attestationKey Optional key to be used for signing the attestation certificate.
     * @param params         Describes the characteristics of the to be generated key. See KeyMint HAL
     *                       for details.
     * @param flags          Additional flags that influence the key generation.
     *                       See {@code KEY_FLAG_*} constants above for details.
     * @param entropy        This array of random bytes is mixed into the entropy source used for key
     *                       generation.
     * @return KeyMetadata includes:
     * <ul>
     * <li>A key descriptor that can be used for subsequent key operations.
     *   If {@code Domain::BLOB} was requested, then the descriptor contains the
     *   generated key, and the caller must assure that the key is persistently
     *   stored accordingly; there is no way to recover the key if the blob is
     *   lost.</li>
     * <li>The generated public certificate if applicable. If {@code Domain::BLOB} was
     *   requested, there is no other copy of this certificate. It is the caller's
     *   responsibility to store it persistently if required.</li>
     * <li>The generated certificate chain if applicable. If {@code Domain::BLOB} was
     *   requested, there is no other copy of this certificate chain. It is the
     *   caller's responsibility to store it persistently if required.</li>
     * <li>The {@code IKeystoreSecurityLevel} field is always null in this context.</li>
     * </ul>
     * @throws RemoteException if the remote operation fails
     */
    KeyMetadata generateKey(@NonNull KeyDescriptor key,
                            @Nullable KeyDescriptor attestationKey,
                            @NonNull KeyParameter[] params,
                            int flags,
                            @NonNull byte[] entropy) throws RemoteException;

    /**
     * Imports the given key. This API call works exactly like {@code generateKey}, only that the key is
     * provided by the caller rather than being generated by KeyMint. We only describe
     * the parameters where they deviate from the ones of {@code generateKey}.
     *
     * @param keyData The key to be imported. Expected encoding is PKCS#8 for asymmetric keys and
     *                raw key bits for symmetric keys.
     * @return KeyMetadata see {@code generateKey}.
     * @throws RemoteException if the remote operation fails
     */
    KeyMetadata importKey(@NonNull KeyDescriptor key,
                          @Nullable KeyDescriptor attestationKey,
                          @NonNull KeyParameter[] params,
                          int flags,
                          @NonNull byte[] keyData) throws RemoteException;

    /**
     * Allows importing keys wrapped with an RSA encryption key that is stored in AndroidKeystore.
     *
     * <h2>Error conditions</h2>
     * {@link ResponseCode#KEY_NOT_FOUND} if the specified wrapping key did not exist.
     *
     * @param key            Governs how the imported key shall be stored. See {@code generateKey} for details.
     * @param wrappingKey    Indicates the key that shall be used for unwrapping the wrapped key
     *                       in a manner similar to starting a new operation with create.
     * @param maskingKey     Reserved for future use. Must be null for now.
     * @param params         These parameters describe the cryptographic operation that shall be performed
     *                       using the wrapping key in order to unwrap the wrapped key.
     * @param authenticators When generating or importing a key that is bound to a specific
     *                       authenticator, the authenticator ID is included in the key parameters.
     *                       Imported wrapped keys can also be authentication bound, however, the
     *                       key parameters were included in the wrapped key at a remote location
     *                       where the device's authenticator ID is not known. Therefore, the
     *                       caller has to provide all of the possible authenticator IDs so that
     *                       KeyMint can pick the right one based on the included key parameters.
     * @return {@link KeyMetadata} see {@link IKeystoreSecurityLevel#generateKey}.
     * @throws RemoteException if the remote operation fails
     */
    KeyMetadata importWrappedKey(@NonNull KeyDescriptor key,
                                 @NonNull KeyDescriptor wrappingKey,
                                 @Nullable byte[] maskingKey,
                                 @NonNull KeyParameter[] params,
                                 @NonNull AuthenticatorSpec[] authenticators) throws RemoteException;

    /**
     * Allows getting a per-boot wrapped ephemeral key from a wrapped storage key.
     *
     * <h2>Error conditions</h2>
     * {@link ResponseCode#PERMISSION_DENIED} if the caller does not have the
     * {@code ConvertStorageKeyToEphemeral} or the {@code ManageBlob} keystore2_key permissions
     * {@link ResponseCode#INVALID_ARGUMENT} if key.domain != Domain::BLOB or a key.blob isn't specified.
     *
     * <p>A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     *
     * @param storageKey The KeyDescriptor with domain Domain::BLOB, and keyblob representing
     *                   the input wrapped storage key to convert
     * @return byte[] representing the wrapped per-boot ephemeral key and an optional upgraded
     * key blob.
     * @throws RemoteException if the remote operation fails
     */
    EphemeralStorageKeyResponse convertStorageKeyToEphemeral(@NonNull KeyDescriptor storageKey) throws RemoteException;

    /**
     * Allows deleting a Domain::BLOB key from the backend underlying this IKeystoreSecurityLevel.
     * While there's another function "deleteKey()" in IKeystoreService, that function doesn't
     * handle Domain::BLOB keys because it doesn't have any information about which underlying
     * device to actually delete the key blob from.
     *
     * <h2>Error conditions</h2>
     * {@link ResponseCode#PERMISSION_DENIED} if the caller does not have the permission {@code DELETE}
     * for the designated key, or the "MANAGE_BLOB" permission to manage
     * Domain::BLOB keys.
     * {@link ResponseCode#INVALID_ARGUMENT} if key.domain != Domain::BLOB or key.blob isn't specified.
     *
     * <p>A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     *
     * @param key representing the key to delete.
     * @throws RemoteException if the remote operation fails
     */
    void deleteKey(@NonNull KeyDescriptor key) throws RemoteException;

    class Stub implements IKeystoreSecurityLevel {
        @Override
        public CreateOperationResponse createOperation(@NonNull KeyDescriptor key, @NonNull KeyParameter[] operationParameters, boolean forced) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public KeyMetadata generateKey(@NonNull KeyDescriptor key, @Nullable KeyDescriptor attestationKey, @NonNull KeyParameter[] params, int flags, @NonNull byte[] entropy) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public KeyMetadata importKey(@NonNull KeyDescriptor key, @Nullable KeyDescriptor attestationKey, @NonNull KeyParameter[] params, int flags, @NonNull byte[] keyData) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public KeyMetadata importWrappedKey(@NonNull KeyDescriptor key, @NonNull KeyDescriptor wrappingKey, @Nullable byte[] maskingKey, @NonNull KeyParameter[] params, @NonNull AuthenticatorSpec[] authenticators) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public EphemeralStorageKeyResponse convertStorageKeyToEphemeral(@NonNull KeyDescriptor storageKey) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public void deleteKey(@NonNull KeyDescriptor key) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public IBinder asBinder() {
            throw new RuntimeException("Stub!");
        }
    }
}
