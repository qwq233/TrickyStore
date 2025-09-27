package android.system.keystore2;

/**
 * Response codes for Keystore 2.0 operations.
 */
public class ResponseCode {
    /* 1 Reserved - formerly NO_ERROR */

    /**
     * TODO: Determine exact semantics of LOCKED and UNINITIALIZED.
     */
    public static final int LOCKED = 2;

    /**
     * TODO: Determine exact semantics of LOCKED and UNINITIALIZED.
     */
    public static final int UNINITIALIZED = 3;

    /**
     * Any unexpected error such as I/O or communication errors.
     * Implementations should log details to logcat.
     */
    public static final int SYSTEM_ERROR = 4;

    /* 5 Reserved - formerly "protocol error" was never used */

    /**
     * Indicates that the caller does not have the required permissions for the attempted request.
     */
    public static final int PERMISSION_DENIED = 6;

    /**
     * Indicates that the requested key does not exist.
     */
    public static final int KEY_NOT_FOUND = 7;

    /**
     * Indicates data corruption in the Keystore 2.0 database.
     */
    public static final int VALUE_CORRUPTED = 8;

    /*
     * 9 Reserved - formerly "undefined action" was never used
     * 10 Reserved - formerly WrongPassword
     * 11-13 Reserved - formerly password retry count indicators: obsolete
     * 14 Reserved - formerly SIGNATURE_INVALID: Keystore does not perform public key operations anymore
     * 15 Reserved - formerly OP_AUTH_NEEDED: now indicated by optional {@code OperationChallenge}
     *               returned by {@code IKeystoreSecurityLevel.create}
     * 16 Reserved
     */

    /**
     * Indicates the key has been permanently invalidated.
     */
    public static final int KEY_PERMANENTLY_INVALIDATED = 17;

    /**
     * Returned by {@code IKeystoreSecurityLevel.create} when all KeyMint operation slots
     * are currently in use and none can be pruned.
     */
    public static final int BACKEND_BUSY = 18;

    /**
     * Logical error on the caller's side. Indicates an attempt to advance an operation
     * (e.g., by calling {@code update}) that is currently processing another {@code update}
     * or {@code finish} request.
     */
    public static final int OPERATION_BUSY = 19;

    /**
     * Indicates that an invalid argument was passed to an API call.
     */
    public static final int INVALID_ARGUMENT = 20;

    /**
     * Indicates that too much data was sent in a single transaction.
     * The binder kernel mechanism cannot unambiguously diagnose this condition,
     * so we limit the maximum amount of data accepted in a single transaction to 32KiB
     * to enforce reasonable limits on clients.
     */
    public static final int TOO_MUCH_DATA = 21;

    /**
     * Previously indicated failures to generate a key due to exhaustion of the
     * remotely provisioned key pool. Starting with API 34, more detailed errors
     * are provided.
     *
     * @deprecated Replaced by other OUT_OF_KEYS_* errors below
     */
    @Deprecated
    public static final int OUT_OF_KEYS = 22;

    /**
     * The device requires a software update as it may contain potentially vulnerable software.
     * This error is returned only on devices that rely solely on remotely-provisioned keys
     * (see <a href="https://android-developers.googleblog.com/2022/03/upgrading-android-attestation-remote.html">
     * Remote Key Provisioning</a>).
     */
    public static final int OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE = 23;

    /**
     * The attestation key pool has been exhausted, and the remote key provisioning server
     * cannot currently be reached. Clients should wait for device connectivity and retry.
     */
    public static final int OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY = 24;

    /**
     * The attestation key pool temporarily has no signed attestation keys available.
     * Key generation may be retried with exponential back-off, as future attempts to
     * fetch attestation keys are expected to succeed.
     *
     * <p>Note: This error is generally the last resort of the underlying provisioner.
     * Future OS updates should consider adding new error codes rather than relying
     * on this status code as a fallback.
     */
    public static final int OUT_OF_KEYS_TRANSIENT_ERROR = 25;

    /**
     * The device will never be able to provision attestation keys using the remote
     * provisioning server. This may be due to causes such as the device not being
     * registered with the remote provisioning backend or the device having been
     * permanently revoked. Clients should not attempt to retry key creation.
     */
    public static final int OUT_OF_KEYS_PERMANENT_ERROR = 26;

    /**
     * Error occurred when getting the attestation application ID. This is a temporary
     * error that can be retried, typically due to a failure in making a binder call
     * to the package manager from the Keystore service. Attestation can be retried
     * as this is considered a warning condition.
     */
    public static final int GET_ATTESTATION_APPLICATION_ID_FAILED = 27;

    /**
     * Indicates that the requested information is not available.
     */
    public static final int INFO_NOT_AVAILABLE = 28;
}
