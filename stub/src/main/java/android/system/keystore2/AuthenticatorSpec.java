package android.system.keystore2;

import android.hardware.security.keymint.HardwareAuthenticatorType;

public class AuthenticatorSpec {
    /**
     * The type of the authenticator in question.
     */
    int authenticatorType = HardwareAuthenticatorType.NONE;

    /**
     * The secure user id by which the given authenticator knows the
     * user that a key should be bound to.
     */
    long authenticatorId;


}
