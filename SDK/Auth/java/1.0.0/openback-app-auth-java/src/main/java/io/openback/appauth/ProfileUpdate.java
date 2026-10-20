package io.openback.appauth;

import java.util.LinkedHashMap;
import java.util.Map;

/** The fields of {@code updateProfile}: only those set are sent. */
public final class ProfileUpdate {
    private final Map<String, Object> fields = new LinkedHashMap<>();

    public ProfileUpdate displayName(String value) {
        fields.put("display_name", value);
        return this;
    }

    public ProfileUpdate photoUrl(String value) {
        fields.put("photo_url", value);
        return this;
    }

    /** "it" or "en". */
    public ProfileUpdate locale(String value) {
        fields.put("locale", value);
        return this;
    }

    Map<String, Object> toBody() {
        return fields;
    }
}
