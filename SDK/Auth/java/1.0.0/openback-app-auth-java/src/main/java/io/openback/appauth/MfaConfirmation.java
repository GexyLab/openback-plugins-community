package io.openback.appauth;

import java.util.Collections;
import java.util.List;

/**
 * The answer of {@code confirmMfa}: the recovery codes (show them once) and, when the enrollment was part of a sign-in
 * ({@code mfaToken}), the sign-in's {@link AuthOutcome}.
 */
public final class MfaConfirmation {
    private final List<String> recoveryCodes;
    private final AuthOutcome outcome;

    MfaConfirmation(List<String> recoveryCodes, AuthOutcome outcome) {
        this.recoveryCodes = recoveryCodes == null ? Collections.emptyList() : Collections.unmodifiableList(recoveryCodes);
        this.outcome = outcome;
    }

    public List<String> getRecoveryCodes() {
        return recoveryCodes;
    }

    /** The sign-in outcome (with an mfaToken), else null. */
    public AuthOutcome getOutcome() {
        return outcome;
    }

    @Override
    public String toString() {
        return "MfaConfirmation{recoveryCodes=" + recoveryCodes.size() + ", outcome=" + outcome + "}";
    }
}
