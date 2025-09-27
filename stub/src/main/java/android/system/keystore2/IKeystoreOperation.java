package android.system.keystore2;

import android.hardware.security.keymint.ErrorCode;
import android.os.IBinder;
import android.os.IInterface;

import androidx.annotation.Nullable;

/**
 * {@code IKeystoreOperation} represents a cryptographic operation using a Keystore key.
 *
 * <p>The lifecycle of an operation begins with {@link IKeystoreSecurityLevel#create}
 * and ends with a call to {@link #finish}, {@link #abort}, or when the reference to
 * the binder object is released.
 *
 * <p>During the operation lifecycle, {@link #update} may be called multiple times.
 * For AEAD operations, {@link #updateAad} may be called to add associated data, but
 * it must be called before the first call to {@link #update}.
 *
 * <h2>Error Conditions</h2>
 * <p>Error conditions are reported as service-specific errors:
 * <ul>
 *   <li>Positive error codes correspond to {@link android.system.keystore2.ResponseCode}
 *       and indicate error conditions diagnosed by the Keystore 2.0 service.</li>
 *   <li>Negative error codes correspond to {@link android.hardware.security.keymint.ErrorCode}
 *       and indicate KeyMint backend errors. Refer to the KeyMint interface specification
 *       for detailed information.</li>
 * </ul>
 */
public interface IKeystoreOperation extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

    /**
     * Advances an operation by adding Additional Authenticated Data (AAD) to AEAD mode
     * encryption or decryption operations. This method cannot be called after {@link #update},
     * and attempting to do so will result in {@link ErrorCode#INVALID_TAG}. This error code
     * is used for historical reasons, dating back when AAD was passed as an additional
     * {@code KeyParameter} with the tag {@code ASSOCIATED_DATA}.
     *
     * <h2>Error Conditions</h2>
     * <ul>
     *   <li>{@link ResponseCode#TOO_MUCH_DATA} if {@code aadInput} exceeds 32KiB.</li>
     *   <li>{@link ResponseCode#OPERATION_BUSY} if {@code updateAad} is called concurrently
     *       with any other {@code IKeystoreOperation} API call.</li>
     *   <li>{@link ErrorCode#INVALID_TAG} if {@code updateAad} is called after {@link #update}
     *       on a given operation.</li>
     *   <li>{@link ErrorCode#INVALID_OPERATION_HANDLE} if the operation has been finalized
     *       for any reason.</li>
     * </ul>
     * <p>
     * Note: Any error condition except {@link ResponseCode#OPERATION_BUSY} finalizes the
     * operation, causing subsequent API calls to return {@link ErrorCode#INVALID_OPERATION_HANDLE}.
     *
     * @param aadInput the Additional Authenticated Data to be added to the operation
     */
    void updateAad(byte[] aadInput);

    /**
     * Advances the operation by processing additional input data. The input data may be
     * plain text to be encrypted or signed, or cipher text to be decrypted. During
     * encryption operations, this method returns the resulting cipher text. During
     * decryption operations, it returns the resulting plain text. No data is returned
     * for signing operations.
     *
     * <h2>Error Conditions</h2>
     * <ul>
     *   <li>{@link ResponseCode#TOO_MUCH_DATA} if the {@code input} exceeds 32KiB.</li>
     *   <li>{@link ResponseCode#OPERATION_BUSY} if {@code updateAad} is called concurrently
     *       with any other {@code IKeystoreOperation} API call.</li>
     *   <li>{@link ErrorCode#INVALID_OPERATION_HANDLE} if the operation has been finalized
     *       for any reason.</li>
     * </ul>
     * <p>
     * Note: Any error condition except {@link ResponseCode#OPERATION_BUSY} finalizes the
     * operation, causing subsequent API calls to return {@link ErrorCode#INVALID_OPERATION_HANDLE}.
     *
     * @param input the input data to process
     * @return the output data, which may be cipher text during encryption, plain text
     * during decryption, or {@code null} for signing operations
     */
    byte[] update(byte[] input);

    /**
     * Finalizes the operation. This method takes a final chunk of input data similar to
     * {@link #update}. The output varies depending on the operation type: it may be a
     * signature for signing operations, plain text for decryption operations, or cipher
     * text for encryption operations.
     *
     * <h2>Error Conditions</h2>
     * <ul>
     *   <li>{@link ResponseCode#TOO_MUCH_DATA} if the {@code input} exceeds 32KiB.</li>
     *   <li>{@link ResponseCode#OPERATION_BUSY} if {@code updateAad} is called concurrently
     *       with any other {@code IKeystoreOperation} API call.</li>
     *   <li>{@link ErrorCode#INVALID_OPERATION_HANDLE} if the operation has already been
     *       finalized for any reason.</li>
     * </ul>
     * <p>
     * Note: {@code finish} finalizes the operation regardless of the outcome, unless
     * {@link ResponseCode#OPERATION_BUSY} is returned.
     *
     * @param input     the final chunk of input data to process
     * @param signature an optional HMAC signature for HMAC verification operations
     * @return the operation result, which may be a signature for signing operations,
     * an AEAD message tag for authenticated encryption, or the final chunk of
     * cipher/plain text for encryption/decryption operations respectively
     */
    byte[] finish(@Nullable byte[] input, @Nullable byte[] signature);

    /**
     * Aborts the operation immediately.
     *
     * <p>Note: {@code abort} finalizes the operation regardless of the outcome, unless
     * {@link ResponseCode#OPERATION_BUSY} is returned.
     */
    void abort();

    class Stub implements IKeystoreOperation {
        public static IKeystoreOperation asInterface(IBinder b) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public void updateAad(byte[] aadInput) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public byte[] update(byte[] input) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public byte[] finish(@Nullable byte[] input, @Nullable byte[] signature) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public void abort() {
            throw new RuntimeException("Stub!");
        }

        @Override
        public IBinder asBinder() {
            throw new RuntimeException("Stub!");
        }
    }
}
