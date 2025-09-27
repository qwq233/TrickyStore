package android.hardware.security.keymint;

/**
 * HardwareAuthenticatorType enum as defined in Keystore2KeyCreationWithAuthInfo of
 * frameworks/proto_logging/stats/atoms.proto.
 */
public class HardwareAuthenticatorType {
    public static final int AUTH_TYPE_UNSPECIFIED = 0;
    public static final int NONE = 1;
    public static final int PASSWORD = 2;
    public static final int FINGERPRINT = 3;
    public static final int ANY = 5;
}
