//
// Decompiled by FernFlower - 531ms
//
package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.Parcel;
import android.os.Parcelable;

public class KeyParameters implements Parcelable {
    public static final Creator<KeyParameters> CREATOR = new Creator<>() {
        @Override
        public KeyParameters createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public KeyParameters[] newArray(int size) {
            throw new RuntimeException();
        }
    };
    public KeyParameter[] keyParameter;

    private int describeContents(Object var1) {
        throw new RuntimeException("Stub!");
    }

    public int describeContents() {
        throw new RuntimeException("Stub!");
    }

    public final int getStability() {
        throw new RuntimeException("Stub!");
    }

    public final void readFromParcel(Parcel var1) {
        throw new RuntimeException("Stub!");
    }

    public final void writeToParcel(Parcel var1, int var2) {
        throw new RuntimeException("Stub!");
    }
}

