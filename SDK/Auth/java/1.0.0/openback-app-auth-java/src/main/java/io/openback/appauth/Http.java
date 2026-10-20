package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** HTTP plumbing shared by the client, the verifier and the web client. */
final class Http {
    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private Http() { }

    static HttpClient defaultClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    static HttpResponse<String> send(HttpClient client, HttpRequest request) {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new AppAuthException(0, "network_error", "Network error: " + e.getClass().getSimpleName(), null, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AppAuthException(0, "interrupted", "Interrupted", null, e);
        }
    }

    /** POST a form to an OAuth endpoint; returns the JSON answer or throws the OAuth error. */
    static JsonNode postForm(HttpClient client, Duration timeout, String url, Map<String, String> form, String authorization) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Util.form(form)));
        if (authorization != null) {
            b.header("Authorization", authorization);
        }
        HttpResponse<String> res = send(client, b.build());
        JsonNode data = Json.parse(res.body());
        if (res.statusCode() < 200 || res.statusCode() >= 300) {
            throw AppAuthException.fromOAuth(res.statusCode(), data);
        }
        return data;
    }

    /**
     * Checks the parameters of a hosted sign-in callback against the transaction: error, state (constant time), iss
     * (RFC 9207). Returns the authorization code.
     */
    static String checkCallback(Map<String, String> params, AuthorizationRequest tx, String issuer) {
        String error = params.get("error");
        if (error != null && !error.isEmpty()) {
            String description = params.get("error_description");
            throw new AppAuthException(400, error, description != null && !description.isEmpty() ? description : error);
        }
        if (tx == null) {
            throw new AppAuthException(400, "no_pending_request", "No sign-in in progress");
        }
        if (!Util.constantTimeEquals(tx.getState(), params.get("state"))) {
            throw new AppAuthException(400, "invalid_state", "Sign-in state mismatch");
        }
        String iss = params.get("iss");
        if (iss != null && !iss.equals(issuer)) {
            throw new AppAuthException(400, "invalid_issuer", "Unexpected issuer");
        }
        String code = params.get("code");
        if (code == null || code.isEmpty()) {
            throw new AppAuthException(400, "invalid_request", "No authorization code in the callback");
        }
        return code;
    }
}
