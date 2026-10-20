package io.openback.appauth;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * A Jakarta Servlet filter (Servlet 5+) that lets through only requests with a valid access token of the pool:
 * {@code Authorization: Bearer <token>} verified by a {@link TokenVerifier}, then the {@link AppUserRequirements}.
 * The user is put in the request attribute {@link AppUser#REQUEST_ATTRIBUTE}.
 *
 * <ul>
 *   <li>missing or invalid token: <b>401</b>, {@code WWW-Authenticate: Bearer error="invalid_token"},
 *       {@code {"error":"invalid_token"}};</li>
 *   <li>requirements not met (roles, permissions, verified email, guest): <b>403</b> {@code {"error":"insufficient_scope"}};</li>
 *   <li>the pool's keys unavailable: <b>503</b> {@code {"error":"temporarily_unavailable"}}.</li>
 * </ul>
 * CORS preflight requests ({@code OPTIONS} with {@code Access-Control-Request-Method}) pass through.
 *
 * <pre>{@code
 * FilterRegistration.Dynamic f = servletContext.addFilter("appAuth",
 *     new RequireAppUserFilter(verifier, AppUserRequirements.defaults().requireRoles("admin")));
 * f.addMappingForUrlPatterns(null, false, "/api/*");
 * }</pre>
 */
public class RequireAppUserFilter implements Filter {
    private final TokenVerifier verifier;
    private final AppUserRequirements requirements;

    public RequireAppUserFilter(TokenVerifier verifier) {
        this(verifier, AppUserRequirements.defaults());
    }

    public RequireAppUserFilter(TokenVerifier verifier, AppUserRequirements requirements) {
        this.verifier = verifier;
        this.requirements = requirements != null ? requirements : AppUserRequirements.defaults();
    }

    /** The user put on the request by the filter, or null. */
    public static AppUser currentUser(ServletRequest request) {
        Object user = request.getAttribute(AppUser.REQUEST_ATTRIBUTE);
        return user instanceof AppUser ? (AppUser) user : null;
    }

    /** The token of an {@code Authorization: Bearer} header, or null. */
    public static String bearerToken(String authorization) {
        if (authorization == null || authorization.length() < 7 || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authorization.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) && request.getHeader("Access-Control-Request-Method") != null) {
            chain.doFilter(req, res);
            return;
        }
        String token = bearerToken(request.getHeader("Authorization"));
        if (token == null) {
            unauthorized(response);
            return;
        }
        AppUser user;
        try {
            user = verifier.verify(token);
        } catch (TokenVerificationException e) {
            if (e.getStatus() == 503) {
                write(response, 503, "{\"error\":\"temporarily_unavailable\"}");
            } else {
                unauthorized(response);
            }
            return;
        }
        if (!requirements.isSatisfiedBy(user)) {
            response.setHeader("WWW-Authenticate", "Bearer error=\"insufficient_scope\"");
            write(response, 403, "{\"error\":\"insufficient_scope\"}");
            return;
        }
        request.setAttribute(AppUser.REQUEST_ATTRIBUTE, user);
        chain.doFilter(req, res);
    }

    private static void unauthorized(HttpServletResponse response) throws IOException {
        response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        write(response, 401, "{\"error\":\"invalid_token\"}");
    }

    private static void write(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
