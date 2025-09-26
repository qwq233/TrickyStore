//
// Decompiled by FernFlower - 527ms
//
package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

public class OperationChallenge implements Parcelable {
    public static final Creator<OperationChallenge> CREATOR = new Creator<>() {
        @Override
        public OperationChallenge createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public OperationChallenge[] newArray(int size) {
            throw new RuntimeException();
        }
    };
    public long challenge = 0L;

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

