package io.openback.appauth;

/**
 * A token refused by {@link TokenVerifier}. Status 401; codes: {@code token_missing}, {@code token_malformed},
 * {@code token_unsupported_alg}, {@code token_invalid_type}, {@code token_unknown_key}, {@code token_invalid_signature},
 * {@code token_invalid_issuer}, {@code token_invalid_audience}, {@code token_expired}, {@code token_not_yet_valid},
 * {@code token_invalid_nonce}, {@code jwks_unavailable} (the keys could not be fetched: status 503).
 */
public class TokenVerificationException extends AppAuthException {
    private static final long serialVersionUID = 1L;

    public TokenVerificationException(String code, String message) {
        super("jwks_unavailable".equals(code) ? 503 : 401, code, message);
    }

    public TokenVerificationException(String code, String message, Throwable cause) {
        super("jwks_unavailable".equals(code) ? 503 : 401, code, message, null, cause);
    }
}
