package io.openback.appauth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequireAppUserFilterTest {
    private FakePool pool;
    private TokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        pool = new FakePool();
        verifier = TokenVerifier.builder(pool.issuer).clientIds("uapp_web").build();
    }

    @AfterEach
    void tearDown() {
        pool.close();
    }

    /** A minimal servlet request/response pair built with dynamic proxies (no servlet container). */
    private static final class Exchange {
        final Map<String, String> requestHeaders = new HashMap<>();
        final Map<String, Object> attributes = new HashMap<>();
        final Map<String, String> responseHeaders = new HashMap<>();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        int status = 200;
        String method = "GET";
        final AtomicBoolean passed = new AtomicBoolean();

        HttpServletRequest request() {
            return (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                    (p, m, a) -> {
                        switch (m.getName()) {
                            case "getHeader": return requestHeaders.get(a[0]);
                            case "getMethod": return method;
                            case "setAttribute": attributes.put((String) a[0], a[1]); return null;
                            case "getAttribute": return attributes.get(a[0]);
                            default: return null;
                        }
                    });
        }

        HttpServletResponse response() {
            ServletOutputStream out = new ServletOutputStream() {
                @Override public boolean isReady() { return true; }
                @Override public void setWriteListener(WriteListener l) { }
                @Override public void write(int b) { body.write(b); }
            };
            return (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{HttpServletResponse.class},
                    (p, m, a) -> {
                        switch (m.getName()) {
                            case "setStatus": status = (Integer) a[0]; return null;
                            case "setHeader": responseHeaders.put((String) a[0], (String) a[1]); return null;
                            case "getOutputStream": return out;
                            default: return null;
                        }
                    });
        }

        FilterChain chain() {
            return (req, res) -> passed.set(true);
        }

        String text() {
            return body.toString(StandardCharsets.UTF_8);
        }
    }

    private Exchange run(RequireAppUserFilter filter, String authorization) throws Exception {
        Exchange ex = new Exchange();
        if (authorization != null) {
            ex.requestHeaders.put("Authorization", authorization);
        }
        filter.doFilter(ex.request(), ex.response(), ex.chain());
        return ex;
    }

    @Test
    void missingOrInvalidTokenIs401() throws Exception {
        RequireAppUserFilter filter = new RequireAppUserFilter(verifier);
        for (String header : new String[]{null, "Basic abc", "Bearer ", "Bearer not.a.token"}) {
            Exchange ex = run(filter, header);
            assertEquals(401, ex.status);
            assertEquals("Bearer error=\"invalid_token\"", ex.responseHeaders.get("WWW-Authenticate"));
            assertEquals("{\"error\":\"invalid_token\"}", ex.text());
            assertFalse(ex.passed.get());
        }
    }

    @Test
    void validTokenPassesWithTheUserAttribute() throws Exception {
        Exchange ex = run(new RequireAppUserFilter(verifier), "bearer " + pool.accessToken("uapp_web"));
        assertTrue(ex.passed.get());
        AppUser user = (AppUser) ex.attributes.get(AppUser.REQUEST_ATTRIBUTE);
        assertEquals("usr_1", user.getId());
    }

    @Test
    void unmetRequirementsAre403() throws Exception {
        String token = pool.accessToken("uapp_web");
        Exchange ex = run(new RequireAppUserFilter(verifier, AppUserRequirements.defaults().requireRoles("admin")), "Bearer " + token);
        assertEquals(403, ex.status);
        assertEquals("{\"error\":\"insufficient_scope\"}", ex.text());
        assertFalse(ex.passed.get());

        Map<String, Object> c = pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 600);
        c.put("anon", true);
        String guest = pool.sign(pool.header("at+jwt"), c, pool.keys.get(0));
        assertEquals(403, run(new RequireAppUserFilter(verifier), "Bearer " + guest).status);
        assertTrue(run(new RequireAppUserFilter(verifier, AppUserRequirements.defaults().allowAnonymous(true)), "Bearer " + guest).passed.get());
    }

    @Test
    void corsPreflightPasses() throws Exception {
        Exchange ex = new Exchange();
        ex.method = "OPTIONS";
        ex.requestHeaders.put("Access-Control-Request-Method", "GET");
        new RequireAppUserFilter(verifier).doFilter(ex.request(), ex.response(), ex.chain());
        assertTrue(ex.passed.get());
    }
}
