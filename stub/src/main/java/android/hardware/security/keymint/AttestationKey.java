//
// Decompiled by Jadx - 783ms
//
package android.hardware.security.keymint;

import android.os.Parcel;
import android.os.Parcelable;

public class AttestationKey implements Parcelable {
    public static final Creator<AttestationKey> CREATOR = new Creator<>() {
        @Override
        public AttestationKey createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public AttestationKey[] newArray(int size) {
            throw new RuntimeException();
        }
    };
    public KeyParameter[] attestKeyParams;
    public byte[] issuerSubjectName;
    public byte[] keyBlob;

    public final int getStability() {
        return 1;
    }

    @Override
    public final void writeToParcel(Parcel _aidl_parcel, int _aidl_flag) {
        throw new RuntimeException("Stub!");
    }

    public final void readFromParcel(Parcel _aidl_parcel) {
        throw new RuntimeException("Stub!");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("Stub!");
    }
}
