package com.example.servlet;

import io.openback.appauth.AppUser;
import io.openback.appauth.AppUserRequirements;
import io.openback.appauth.RequireAppUserFilter;
import io.openback.appauth.TokenVerifier;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/** Plain Jakarta Servlet (Tomcat 10+, Jetty 11+): every /api/* request needs an app user with the role "member". */
@WebListener
public class AppAuthInitializer implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent event) {
        TokenVerifier verifier = TokenVerifier.builder("https://api.example.com/gateway/shop/auth/main")
                .clientIds("uapp_your_web_app")
                .build();
        FilterRegistration.Dynamic filter = event.getServletContext().addFilter("openbackAppAuth",
                new RequireAppUserFilter(verifier, AppUserRequirements.defaults().requireRoles("member")));
        filter.addMappingForUrlPatterns(null, false, "/api/*");
    }

    @WebServlet("/api/me")
    public static class MeServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            AppUser user = RequireAppUserFilter.currentUser(req);
            res.setContentType("application/json");
            res.getWriter().write("{\"id\":\"" + user.getId() + "\"}");
        }
    }
}
