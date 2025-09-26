package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyDescriptor implements Parcelable {
    public String alias;
    public byte[] blob;

    /**
     * Describes the different domain types for key access:
     *
     * <dl>
     * <dt>{@code Domain.APP} (0)</dt>
     * <dd>The {@code nspace} field is ignored, and the caller's UID is used instead.
     *     The access tuple is {@code (App, caller_uid, alias)}.</dd>
     *
     * <dt>{@code Domain.SELINUX} (2)</dt>
     * <dd>The {@code nspace} field is used. The access tuple is {@code (SELinux, nspace, alias)}.</dd>
     *
     * <dt>{@code Domain.GRANT} (1)</dt>
     * <dd>The {@code nspace} field holds a grant ID. The key ID is looked up in the grant database
     *     and the key is accessed by the key ID.</dd>
     *
     * <dt>{@code Domain.KEY_ID} (4)</dt>
     * <dd>The {@code nspace} field holds the {@code key_id} which can be used to access the key directly.
     *     While alias-based key descriptors can yield different keys every time they are used because
     *     aliases can be rebound to newly generated or imported keys, the key ID is unique for a given key.
     *     Using a key by its key ID in subsequent Keystore calls guarantees that the private/secret key
     *     material used corresponds to the metadata previously loaded using {@code loadKeyEntry}.
     *     The key ID does not protect against rebinding, but if the corresponding alias was rebound,
     *     the key ID ceases to be valid, thereby indicating to the caller that the previously loaded
     *     metadata and public key material no longer corresponds to the key entry.
     *
     *     <p>Note: Implementations must choose the key ID as a 64-bit random number, so there is a
     *     minimal non-zero chance of collision with a previously existing key ID.</p>
     * </dd>
     *
     * <dt>{@code Domain.BLOB} (3)</dt>
     * <dd>The {@code blob} field holds the key blob. It is not stored in the database.</dd>
     * </dl>
     *
     * <p>The key descriptor is used by various API calls. In all cases, the implementation must perform
     * appropriate access control to ensure that the caller has access to the given key for the given request.
     * In the case of {@code Domain.BLOB}, the implementation must additionally check if the caller has
     * the {@code ManageBlob} permission. See {@link KeyPermission} for details.</p>
     */
    public int domain = 0;
    public long nspace = 0;

    public static final Creator<KeyDescriptor> CREATOR = new Creator<KeyDescriptor>() {
        @Override
        public KeyDescriptor createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public KeyDescriptor[] newArray(int size) {
            throw new RuntimeException();
        }
    };

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        throw new RuntimeException("");
    }
}
