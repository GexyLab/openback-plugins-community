package io.openback.appauth;

/** A two-step verification enrollment: show {@link #getOtpauthUri()} as a QR code (or the secret), then confirm a code. */
public final class MfaEnrollment {
    private String secret;
    private String otpauthUri;

    /** The TOTP secret (base32), for manual entry. A secret: never log it. */
    public String getSecret() {
        return secret;
    }

    /** The {@code otpauth://} URI for authenticator apps (QR code). */
    public String getOtpauthUri() {
        return otpauthUri;
    }

    @Override
    public String toString() {
        return "MfaEnrollment{***}";
    }
}
