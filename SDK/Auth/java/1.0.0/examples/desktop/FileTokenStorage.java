import io.openback.appauth.TokenStorage;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Properties;

/**
 * Example: a TokenStorage in a file of the user's profile, written atomically (temp file + move), readable only by the
 * user on POSIX systems. The values are secrets: for real apps prefer the OS keychain (macOS Keychain, Windows
 * Credential Manager / DPAPI, libsecret) or encrypt the file.
 *
 *   AppAuthClient.builder(issuer, clientId).storage(new FileTokenStorage(Path.of(System.getProperty("user.home"), ".myapp", "session"))).build();
 */
public final class FileTokenStorage implements TokenStorage {
    private final Path file;

    public FileTokenStorage(Path file) {
        this.file = file;
    }

    private Properties read() {
        Properties p = new Properties();
        if (Files.exists(file)) {
            try (var in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                p.load(in);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return p;
    }

    private void write(Properties p) {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = Files.createTempFile(file.getParent(), "session", ".tmp");
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // Windows: the profile directory's ACL applies
            }
            try (var out = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                p.store(out, null);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public synchronized String get(String key) {
        return read().getProperty(key);
    }

    @Override
    public synchronized void set(String key, String value) {
        Properties p = read();
        p.setProperty(key, value);
        write(p);
    }

    @Override
    public synchronized void remove(String key) {
        Properties p = read();
        if (p.remove(key) != null) {
            write(p);
        }
    }
}
