package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The outcome of a sign-up or sign-in step. Only {@link Status#OK} signs the user in (the SDK keeps the session); every
 * other status tells the app how to continue:
 * <ul>
 *   <li>{@link Status#VERIFICATION_REQUIRED}: the user must verify the email address first (a link/code was sent);</li>
 *   <li>{@link Status#MFA_REQUIRED}: ask the authenticator code, then {@code verifyMfa(getMfaToken(), code)};</li>
 *   <li>{@link Status#MFA_ENROLL_REQUIRED}: the pool requires two-step verification: {@code enrollMfa(getMfaToken())}
 *       then {@code confirmMfa(code, getMfaToken())};</li>
 *   <li>{@link Status#PASSWORD_CHANGE_REQUIRED}: {@code changeForcedPassword(getChangeToken(), newPassword)}.</li>
 * </ul>
 * The tokens are never exposed here (use {@link AppAuthClient#getAccessToken()}).
 */
public final class AuthOutcome {
    /** The outcome's status. */
    public enum Status {
        OK("ok"),
        VERIFICATION_REQUIRED("verification_required"),
        MFA_REQUIRED("mfa_required"),
        MFA_ENROLL_REQUIRED("mfa_enroll_required"),
        PASSWORD_CHANGE_REQUIRED("password_change_required"),
        /** A status this version of the SDK does not know: see {@link AuthOutcome#getRawStatus()}. */
        UNKNOWN("");

        private final String wire;

        Status(String wire) {
            this.wire = wire;
        }

        /** The status as the service writes it. */
        public String wire() {
            return wire;
        }

        static Status of(String value) {
            for (Status s : values()) {
                if (s != UNKNOWN && s.wire.equals(value)) {
                    return s;
                }
            }
            return UNKNOWN;
        }
    }

    private static final String[] SECRET_FIELDS = {"access_token", "refresh_token", "id_token"};

    private final Status status;
    private final String rawStatus;
    private final PoolUser user;
    private final ActiveOrg org;
    private final String mfaToken;
    private final String changeToken;
    private final List<String> recoveryCodes;
    private final JsonNode details;

    private AuthOutcome(JsonNode data) {
        this.rawStatus = Json.text(data, "status");
        this.status = Status.of(rawStatus);
        this.user = Json.convert(data.get("user"), PoolUser.class);
        this.org = Json.convert(data.get("org"), ActiveOrg.class);
        this.mfaToken = Json.text(data, "mfa_token");
        this.changeToken = Json.text(data, "change_token");
        List<String> codes = new ArrayList<>();
        JsonNode rc = data.get("recovery_codes");
        if (rc != null && rc.isArray()) {
            rc.forEach(n -> codes.add(n.asText()));
        }
        this.recoveryCodes = Collections.unmodifiableList(codes);
        ObjectNode copy = data.isObject() ? ((ObjectNode) data).deepCopy() : Json.MAPPER.createObjectNode();
        for (String f : SECRET_FIELDS) {
            copy.remove(f);
        }
        this.details = copy;
    }

    static AuthOutcome of(JsonNode data) {
        return new AuthOutcome(data == null || !data.isObject() ? Json.MAPPER.createObjectNode() : data);
    }

    public Status getStatus() {
        return status;
    }

    /** The status string as answered. */
    public String getRawStatus() {
        return rawStatus;
    }

    /** True when the user is signed in. */
    public boolean isOk() {
        return status == Status.OK;
    }

    /** The user ({@link Status#OK}). */
    public PoolUser getUser() {
        return user;
    }

    /** The active organization (B2B pools, {@link Status#OK}). */
    public ActiveOrg getOrg() {
        return org;
    }

    /** {@link Status#MFA_REQUIRED} / {@link Status#MFA_ENROLL_REQUIRED}. */
    public String getMfaToken() {
        return mfaToken;
    }

    /** {@link Status#PASSWORD_CHANGE_REQUIRED}. */
    public String getChangeToken() {
        return changeToken;
    }

    /** After {@code confirmMfa(code, mfaToken)}: the one-time recovery codes to show the user once. */
    public List<String> getRecoveryCodes() {
        return recoveryCodes;
    }

    /** The whole answer without the tokens (e.g. {@code message}, {@code email}). */
    public JsonNode getDetails() {
        return details;
    }

    @Override
    public String toString() {
        return "AuthOutcome{status=" + rawStatus + "}";
    }
}
