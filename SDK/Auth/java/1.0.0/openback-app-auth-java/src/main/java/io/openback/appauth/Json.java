package io.openback.appauth;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.NullNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** The SDK's JSON mapper: snake_case fields (the service's naming), unknown fields ignored, nulls omitted. */
final class Json {
    static final ObjectMapper MAPPER = JsonMapper.builder()
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .visibility(PropertyAccessor.ALL, Visibility.NONE)
            .visibility(PropertyAccessor.FIELD, Visibility.ANY)
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .build();

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<Map<String, Object>>() { };

    private Json() { }

    static JsonNode parse(String text) {
        if (text == null || text.isBlank()) {
            return NullNode.getInstance();
        }
        try {
            return MAPPER.readTree(text);
        } catch (JsonProcessingException e) {
            return NullNode.getInstance();
        }
    }

    static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("JSON serialization failed", e);
        }
    }

    static <T> T convert(JsonNode node, Class<T> type) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        return MAPPER.convertValue(node, type);
    }

    static Map<String, Object> toMap(JsonNode node) {
        if (node == null || !node.isObject()) {
            return Collections.emptyMap();
        }
        return MAPPER.convertValue(node, MAP);
    }

    /** A JSON object from key/value pairs, skipping null values (like an "undefined" field in JavaScript). */
    static Map<String, Object> object(Object... keyValues) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keyValues.length; i += 2) {
            if (keyValues[i + 1] != null) {
                out.put((String) keyValues[i], keyValues[i + 1]);
            }
        }
        return out;
    }

    static String text(JsonNode node, String field) {
        JsonNode v = node == null ? null : node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }
}
