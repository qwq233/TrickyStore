//
// Decompiled by FernFlower - 648ms
//
package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

public class CreateOperationResponse implements Parcelable {
    public static final Creator<CreateOperationResponse> CREATOR = new Creator<>() {
        @Override
        public CreateOperationResponse createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public CreateOperationResponse[] newArray(int size) {
            throw new RuntimeException();
        }
    };
    public IKeystoreOperation iOperation;
    public OperationChallenge operationChallenge;
    public KeyParameters parameters;
    public byte[] upgradedBlob;

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

