package com.example.servlet;

import io.openback.appauth.AppAuthException;
import io.openback.appauth.AuthorizationOptions;
import io.openback.appauth.AuthorizationRequest;
import io.openback.appauth.OidcWebClient;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A "web" app (confidential: client secret from your secret store, never in the code) signing users in on the pool's
 * hosted page. Register https://app.example.com/callback as a redirect URI and https://app.example.com/ as a
 * post-logout redirect URI.
 */
public class WebAppSignIn {
    static final OidcWebClient OIDC = OidcWebClient.builder(
            "https://api.example.com/gateway/shop/auth/main", "uapp_your_web_app",
            System.getenv("OPENBACK_CLIENT_SECRET"), "https://app.example.com/callback").build();

    @WebServlet("/login")
    public static class Login extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            AuthorizationRequest tx = OIDC.authorizationUrl(new AuthorizationOptions().provider(req.getParameter("provider")));
            req.getSession(true).setAttribute("oidc.tx", tx.toJson());          // server-side only
            res.sendRedirect(tx.getUrl());
        }
    }

    @WebServlet("/callback")
    public static class Callback extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            HttpSession session = req.getSession(false);
            if (session == null) {
                res.sendError(400);
                return;
            }
            AuthorizationRequest tx = AuthorizationRequest.fromJson((String) session.getAttribute("oidc.tx"));
            session.removeAttribute("oidc.tx");                                 // one use
            Map<String, String> params = new HashMap<>();
            req.getParameterMap().forEach((k, v) -> params.put(k, v[0]));
            try {
                OidcWebClient.Result result = OIDC.handleCallback(params, tx);
                req.changeSessionId();                                          // new session id after sign-in
                session.setAttribute("user.id", result.getUserId());
                session.setAttribute("user.refresh", result.getTokens().getRefreshToken());   // rotate on every refresh
                session.setAttribute("user.idToken", result.getTokens().getIdToken());
                res.sendRedirect("/");
            } catch (AppAuthException e) {
                res.sendError(401, "Sign-in failed: " + e.getCode());
            }
        }
    }

    @WebServlet("/logout")
    public static class Logout extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            HttpSession session = req.getSession(false);
            String idToken = null;
            if (session != null) {
                idToken = (String) session.getAttribute("user.idToken");
                String refresh = (String) session.getAttribute("user.refresh");
                if (refresh != null) {
                    try {
                        OIDC.revoke(refresh);
                    } catch (AppAuthException ignored) {
                        // best effort
                    }
                }
                session.invalidate();
            }
            res.sendRedirect(OIDC.logoutUrl(idToken, "https://app.example.com/", null));
        }
    }
}
