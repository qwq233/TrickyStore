package android.system.keystore2;

import androidx.annotation.Nullable;

public class EphemeralStorageKeyResponse {
    /**
     * The ephemeral storage key.
     */
    public byte[] ephemeralKey;

    /**
     * An optional opaque blob. If the key given to ISecurityLevel::convertStorageKeyToEphemeral
     * was upgraded, then this field is present, and represents the upgraded version of that key.
     */
    @Nullable
    public byte[] upgradedBlob;
}
