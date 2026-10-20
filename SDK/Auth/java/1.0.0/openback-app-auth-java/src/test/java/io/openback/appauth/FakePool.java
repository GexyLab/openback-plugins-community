package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An in-process fake of a user pool on 127.0.0.1 (never the network): routes answered by handlers, requests recorded,
 * an ES256 P-256 key pair generated per test to sign tokens and serve the JWKS.
 */
final class FakePool implements AutoCloseable {
    /** A recorded request. */
    static final class Req {
        final String method;
        final String path;
        final String query;
        final Map<String, String> headers;
        final String body;

        Req(String method, String path, String query, Map<String, String> headers, String body) {
            this.method = method;
            this.path = path;
            this.query = query;
            this.headers = headers;
            this.body = body;
        }

        JsonNode json() {
            return Json.parse(body);
        }

        Map<String, String> form() {
            return Util.queryParams("http://x/?" + body);
        }

        String header(String name) {
            return headers.get(name.toLowerCase());
        }
    }

    /** A canned answer. */
    static final class Res {
        final int status;
        final String body;

        Res(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    @FunctionalInterface
    interface Handler {
        Res handle(Req req) throws Exception;
    }

    final HttpServer server;
    final String base;
    final String issuer;
    final List<Req> requests = new CopyOnWriteArrayList<>();
    final List<Throwable> failures = new CopyOnWriteArrayList<>();
    final Map<String, Handler> routes = new ConcurrentHashMap<>();
    final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    final List<KeyPair> keys = new CopyOnWriteArrayList<>();
    final List<String> kids = new CopyOnWriteArrayList<>();

    FakePool() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.createContext("/", this::dispatch);
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        issuer = base + "/gateway/shop/auth/main";
        addKey("k1");
        api("GET", "/.well-known/jwks.json", r -> new Res(200, jwks()));
    }

    static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    void addKey(String kid) throws Exception {
        keys.add(0, newKeyPair());
        kids.add(0, kid);
    }

    String jwks() {
        StringBuilder sb = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < keys.size(); i++) {
            ECPublicKey pub = (ECPublicKey) keys.get(i).getPublic();
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"use\":\"sig\",\"kid\":\"").append(kids.get(i))
                    .append("\",\"x\":\"").append(Util.b64url(fixed(pub.getW().getAffineX())))
                    .append("\",\"y\":\"").append(Util.b64url(fixed(pub.getW().getAffineY()))).append("\"}");
        }
        return sb.append("]}").toString();
    }

    private static byte[] fixed(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    void route(String method, String path, Handler handler) {
        routes.put(method + " " + path, handler);
    }

    /** Route under the issuer, e.g. "/api/v1/me". */
    void api(String method, String path, Handler handler) {
        route(method, "/gateway/shop/auth/main" + path, handler);
    }

    int hits(String method, String issuerPath) {
        AtomicInteger n = hits.get(method + " /gateway/shop/auth/main" + issuerPath);
        return n == null ? 0 : n.get();
    }

    int rawHits(String method, String path) {
        AtomicInteger n = hits.get(method + " " + path);
        return n == null ? 0 : n.get();
    }

    private void dispatch(HttpExchange ex) throws IOException {
        try {
            String body;
            try (InputStream in = ex.getRequestBody()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            Map<String, String> headers = new LinkedHashMap<>();
            ex.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), v.get(0)));
            String path = ex.getRequestURI().getRawPath();
            String key = ex.getRequestMethod() + " " + path;
            hits.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
            Req req = new Req(ex.getRequestMethod(), path, ex.getRequestURI().getRawQuery(), headers, body);
            requests.add(req);
            Handler h = routes.get(key);
            Res res = h == null ? new Res(404, "{\"detail\":{\"code\":\"not_found\",\"message\":\"Not found\"}}") : h.handle(req);
            if (res == null) {          // simulate a dropped connection
                ex.close();
                return;
            }
            byte[] out = res.body == null ? new byte[0] : res.body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(res.status, out.length == 0 ? -1 : out.length);
            if (out.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            }
        } catch (Throwable e) {
            failures.add(e);
            try {
                ex.sendResponseHeaders(500, -1);
            } catch (IOException ignored) {
                // headers already sent
            }
        } finally {
            ex.close();
        }
    }

    // --- tokens ------------------------------------------------------------------------------------------------------

    static String b64json(String json) {
        return Util.b64url(json.getBytes(StandardCharsets.UTF_8));
    }

    String sign(Map<String, Object> header, Map<String, Object> claims, KeyPair key) throws Exception {
        String input = b64json(Json.write(header)) + "." + b64json(Json.write(claims));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key.getPrivate());
        s.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Util.b64url(Es256.derToJose(s.sign()));
    }

    Map<String, Object> accessClaims(String clientId, long expEpochSeconds) {
        Map<String, Object> c = new LinkedHashMap<>();
        long now = System.currentTimeMillis() / 1000;
        c.put("iss", issuer);
        c.put("sub", "usr_1");
        c.put("aud", clientId);
        c.put("azp", clientId);
        c.put("exp", expEpochSeconds);
        c.put("iat", now);
        c.put("jti", "at_1");
        c.put("sid", "ses_1");
        c.put("pool", "upool_1");
        c.put("sv", 1);
        c.put("org_id", "org_1");
        c.put("roles", new ArrayList<>(List.of("member")));
        c.put("permissions", new ArrayList<>(List.of("invoices.read")));
        c.put("email", "ada@example.com");
        c.put("email_verified", true);
        c.put("amr", new ArrayList<>(List.of("pwd")));
        c.put("scope", "openid profile email");
        c.put("attr", new LinkedHashMap<>(Map.of("plan", "pro")));
        return c;
    }

    Map<String, Object> header(String typ) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("alg", "ES256");
        h.put("typ", typ);
        h.put("kid", kids.get(0));
        return h;
    }

    String accessToken(String clientId, long expEpochSeconds) throws Exception {
        return sign(header("at+jwt"), accessClaims(clientId, expEpochSeconds), keys.get(0));
    }

    String accessToken(String clientId) throws Exception {
        return accessToken(clientId, System.currentTimeMillis() / 1000 + 900);
    }

    String idToken(String clientId, String nonce) throws Exception {
        Map<String, Object> c = accessClaims(clientId, System.currentTimeMillis() / 1000 + 300);
        c.remove("permissions");
        c.remove("scope");
        if (nonce != null) {
            c.put("nonce", nonce);
        }
        return sign(header("JWT"), c, keys.get(0));
    }

    static String userJson(String id) {
        return "{\"id\":\"" + id + "\",\"email\":\"ada@example.com\",\"email_verified\":true,\"display_name\":\"Ada\","
                + "\"photo_url\":null,\"locale\":\"en\",\"attributes\":{\"plan\":\"pro\"},\"anonymous\":false,"
                + "\"created_at\":\"2026-10-01T10:00:00Z\",\"last_login_at\":null,\"mfa\":{\"totp\":false}}";
    }

    static Map<String, Object> noNulls(Map<String, Object> m) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        out.values().removeIf(v -> v == null);
        return Collections.unmodifiableMap(out);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
