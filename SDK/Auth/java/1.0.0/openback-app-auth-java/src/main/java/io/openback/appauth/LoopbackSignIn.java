package io.openback.appauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Hosted sign-in for desktop and CLI apps (RFC 8252 loopback redirect): a one-shot HTTP listener on
 * {@code 127.0.0.1:<port>}, the system browser opened on the sign-in page, the callback handed to
 * {@link AppAuthClient#handleRedirectCallback(String)}.
 *
 * <p>Register EXACTLY {@code http://127.0.0.1:<port><path>} as a redirect URI of a {@code native} app in the pool (the
 * service matches redirect URIs exactly, so pick a fixed port). Uses {@code com.sun.net.httpserver} (module
 * {@code jdk.httpserver}) and {@code java.awt.Desktop} (module {@code java.desktop}); on a headless machine pass your
 * own {@link BrowserOpener} (e.g. print the URL).
 *
 * <pre>{@code
 * try (LoopbackSignIn loopback = LoopbackSignIn.start(53682, "/callback")) {
 *     PoolUser user = loopback.signIn(auth, new AuthorizationOptions(), Duration.ofMinutes(5));
 * }
 * }</pre>
 */
public final class LoopbackSignIn implements AutoCloseable {
    /** Opens a URL in a browser. */
    @FunctionalInterface
    public interface BrowserOpener {
        void open(String url) throws IOException;
    }

    private static final String DONE_PAGE = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed in</title></head>"
            + "<body style=\"font-family:sans-serif;margin:3em\"><h1>You can close this window</h1>"
            + "<p>Return to the application.</p></body></html>";

    private final HttpServer server;
    private final String path;
    private final String redirectUri;
    private final CompletableFuture<String> callback = new CompletableFuture<>();

    private LoopbackSignIn(HttpServer server, String path) {
        this.server = server;
        this.path = path;
        this.redirectUri = "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    /**
     * Starts the listener on {@code 127.0.0.1:port} ({@code 0}: a free port, usable only if the pool accepts that exact
     * address, so normally a fixed port).
     */
    public static LoopbackSignIn start(int port, String path) throws IOException {
        String p = path == null || path.isEmpty() ? "/callback" : (path.startsWith("/") ? path : "/" + path);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        LoopbackSignIn self = new LoopbackSignIn(server, p);
        server.createContext("/", self::handle);
        server.start();
        return self;
    }

    /** {@code http://127.0.0.1:<port><path>}. */
    public String getRedirectUri() {
        return redirectUri;
    }

    private void handle(HttpExchange ex) throws IOException {
        try {
            if (!"GET".equals(ex.getRequestMethod()) || !path.equals(ex.getRequestURI().getRawPath()) || callback.isDone()) {
                ex.sendResponseHeaders(404, -1);
                return;
            }
            byte[] body = DONE_PAGE.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            ex.getResponseHeaders().set("Referrer-Policy", "no-referrer");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(body);
            }
            callback.complete(redirectUri + (ex.getRequestURI().getRawQuery() != null ? "?" + ex.getRequestURI().getRawQuery() : ""));
        } finally {
            ex.close();
        }
    }

    /** Waits for the browser to come back; returns the full callback URL. */
    public String awaitCallback(Duration timeout) {
        try {
            return callback.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            throw new AppAuthException(0, "timeout", "The sign-in was not completed in time");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AppAuthException(0, "interrupted", "Interrupted");
        } catch (ExecutionException e) {
            throw new AppAuthException(0, "callback_failed", "Callback failed", null, e.getCause());
        }
    }

    /** The whole flow with the desktop's default browser. */
    public PoolUser signIn(AppAuthClient client, AuthorizationOptions options, Duration timeout) throws IOException {
        return signIn(client, options, timeout, LoopbackSignIn::openWithDesktop);
    }

    /** The whole flow: build the request (this listener's redirect URI), open the browser, wait, complete. */
    public PoolUser signIn(AppAuthClient client, AuthorizationOptions options, Duration timeout, BrowserOpener browser) throws IOException {
        AuthorizationOptions o = options != null ? options : new AuthorizationOptions();
        o.redirectUri(redirectUri);
        AuthorizationRequest request = client.buildAuthorizationRequest(o);
        browser.open(request.getUrl());
        return client.handleRedirectCallback(awaitCallback(timeout));
    }

    /** Opens a URL with {@code java.awt.Desktop} (throws on a headless machine). */
    public static void openWithDesktop(String url) throws IOException {
        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            throw new IOException("No desktop browser available: open the URL yourself");
        }
        Desktop.getDesktop().browse(URI.create(url));
    }

    /** Stops the listener. */
    @Override
    public void close() {
        server.stop(0);
    }
}
