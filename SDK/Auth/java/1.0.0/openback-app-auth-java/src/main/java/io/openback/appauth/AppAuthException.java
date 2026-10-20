package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * An error answered by the user pool, or a local failure of the SDK.
 *
 * <ul>
 *   <li>{@link #getStatus()}: the HTTP status (0 for a network or local failure);</li>
 *   <li>{@link #getCode()}: the service's code ({@code invalid_credentials}, {@code weak_password}, {@code token_expired}...),
 *       an OAuth error ({@code invalid_grant}...) or {@code http_<status>} when the answer has none. Local codes:
 *       {@code network_error}, {@code interrupted}, {@code not_signed_in}, {@code invalid_state}, {@code invalid_issuer},
 *       {@code invalid_nonce}, {@code no_pending_request}, {@code invalid_request};</li>
 *   <li>{@link #getDetail()}: the raw {@code detail} of the answer (for {@code weak_password}: {@code detail.problems}).</li>
 * </ul>
 */
public class AppAuthException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int status;
    private final String code;
    private final transient JsonNode detail;

    public AppAuthException(int status, String code, String message) {
        this(status, code, message, null, null);
    }

    public AppAuthException(int status, String code, String message, JsonNode detail, Throwable cause) {
        super(message != null && !message.isEmpty() ? message : (code != null ? code : "HTTP " + status), cause);
        this.status = status;
        this.code = code != null ? code : "http_" + status;
        this.detail = detail;
    }

    /** Builds the exception from a JSON API error answer: {@code {"detail": {"code", "message"}}}, a string or a list. */
    static AppAuthException fromApi(int status, JsonNode body) {
        JsonNode detail = body != null && body.isObject() ? body.get("detail") : null;
        String code = null;
        String message = null;
        if (detail != null && detail.isObject()) {
            code = Json.text(detail, "code");
            message = Json.text(detail, "message");
        } else if (detail != null && detail.isTextual()) {
            message = detail.asText();
        } else if (detail != null && detail.isArray()) {
            message = "Invalid request";
        }
        if (code == null && body != null && body.isObject() && body.hasNonNull("error")) {
            code = body.get("error").asText();
            message = message != null ? message : Json.text(body, "error_description");
        }
        return new AppAuthException(status, code != null ? code : "http_" + status, message, detail, null);
    }

    /** Builds the exception from an OAuth error answer: {@code {"error", "error_description"}}. */
    static AppAuthException fromOAuth(int status, JsonNode body) {
        String error = Json.text(body, "error");
        if (error == null) {
            return fromApi(status, body);
        }
        String description = Json.text(body, "error_description");
        return new AppAuthException(status, error, description != null ? description : error, body, null);
    }

    public int getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    public JsonNode getDetail() {
        return detail;
    }

    /** True when the error means the local session is dead (a 401 {@code token_*} or {@code invalid_refresh_token}). */
    public boolean isSessionEnded() {
        return status == 401 && (code.startsWith("token_") || "invalid_refresh_token".equals(code));
    }
}
