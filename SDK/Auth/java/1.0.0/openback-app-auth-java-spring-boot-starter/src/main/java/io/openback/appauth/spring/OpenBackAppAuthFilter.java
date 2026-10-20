package io.openback.appauth.spring;

import io.openback.appauth.RequireAppUserFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The Spring Security filter of the starter: a request with {@code Authorization: Bearer <token>} is authenticated by
 * {@link AppUserAuthenticationProvider} and gets an {@link AppUserAuthentication} in the security context; an invalid
 * token answers <b>401</b> ({@code WWW-Authenticate: Bearer error="invalid_token"}, {@code {"error":"invalid_token"}}),
 * a user failing the global requirements <b>403</b> {@code {"error":"insufficient_scope"}}. A request without a token
 * goes on unauthenticated: the authorization rules decide ({@link #ENTRY_POINT} answers 401 the same way).
 *
 * <p>Add it to your chain before {@code UsernamePasswordAuthenticationFilter}:
 * <pre>{@code
 * http.addFilterBefore(appAuthFilter, UsernamePasswordAuthenticationFilter.class)
 *     .exceptionHandling(e -> e.authenticationEntryPoint(OpenBackAppAuthFilter.ENTRY_POINT)
 *                              .accessDeniedHandler(OpenBackAppAuthFilter.ACCESS_DENIED));
 * }</pre>
 */
public class OpenBackAppAuthFilter extends OncePerRequestFilter {
    /** 401 {@code {"error":"invalid_token"}} with {@code WWW-Authenticate: Bearer error="invalid_token"}. */
    public static final AuthenticationEntryPoint ENTRY_POINT = (request, response, e) -> unauthorized(response);

    /** 403 {@code {"error":"insufficient_scope"}} (roles/permissions required by your rules). */
    public static final AccessDeniedHandler ACCESS_DENIED = (request, response, e) -> forbidden(response);

    private final AppUserAuthenticationProvider provider;
    private SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();

    public OpenBackAppAuthFilter(AppUserAuthenticationProvider provider) {
        this.provider = provider;
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
        this.contextHolder = strategy;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        String token = RequireAppUserFilter.bearerToken(header);
        if (token == null) {
            if (header != null && header.regionMatches(true, 0, "Bearer", 0, 6)) {
                unauthorized(response);              // "Bearer" with no token
                return;
            }
            chain.doFilter(request, response);
            return;
        }
        Authentication result;
        try {
            result = provider.authenticate(AppUserAuthentication.unauthenticated(token));
        } catch (AppUserAuthenticationProvider.AppUserRequirementsException e) {
            contextHolder.clearContext();
            forbidden(response);
            return;
        } catch (AuthenticationServiceException e) {
            contextHolder.clearContext();
            write(response, 503, "{\"error\":\"temporarily_unavailable\"}");
            return;
        } catch (AuthenticationException e) {
            contextHolder.clearContext();
            unauthorized(response);
            return;
        }
        SecurityContext context = contextHolder.createEmptyContext();
        context.setAuthentication(result);
        contextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    static void unauthorized(HttpServletResponse response) throws IOException {
        response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        write(response, 401, "{\"error\":\"invalid_token\"}");
    }

    static void forbidden(HttpServletResponse response) throws IOException {
        response.setHeader("WWW-Authenticate", "Bearer error=\"insufficient_scope\"");
        write(response, 403, "{\"error\":\"insufficient_scope\"}");
    }

    private static void write(HttpServletResponse response, int status, String json) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
