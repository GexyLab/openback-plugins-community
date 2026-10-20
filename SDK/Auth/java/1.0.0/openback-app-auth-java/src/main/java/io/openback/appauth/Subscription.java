package io.openback.appauth;

/** A listener registration; {@link #close()} unsubscribes (idempotent). */
@FunctionalInterface
public interface Subscription extends AutoCloseable {
    @Override
    void close();
}
