package io.openback.appauth;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** The default {@link TokenStorage}: a map in memory, lost when the process ends. Thread-safe. */
public final class InMemoryTokenStorage implements TokenStorage {
    private final ConcurrentMap<String, String> data = new ConcurrentHashMap<>();

    @Override
    public String get(String key) {
        return data.get(key);
    }

    @Override
    public void set(String key, String value) {
        data.put(key, value);
    }

    @Override
    public void remove(String key) {
        data.remove(key);
    }
}
