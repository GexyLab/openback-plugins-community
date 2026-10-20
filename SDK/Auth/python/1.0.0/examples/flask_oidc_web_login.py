"""Flask: a "web" app signing users in through the pool's hosted page (OpenID Connect, code + PKCE, client secret).

    pip install "openback-app-auth-python[flask]"
    set OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main
    set OPENBACK_CLIENT_ID=uapp_...              (an app of kind "web")
    set OPENBACK_CLIENT_SECRET=...               (never commit it)
    set FLASK_SECRET_KEY=<random string>
    flask --app flask_oidc_web_login run --port 5000

Register in the pool: redirect URI http://localhost:5000/callback, post-logout redirect URI http://localhost:5000/.

Flask's default session is a SIGNED (not encrypted) cookie: this example keeps only the PKCE transaction and the
user's public claims in it. Tokens go to a server-side store (a dict here; use Redis/your DB in production).
"""
import os
import secrets

from flask import Flask, abort, redirect, request, session, url_for

from openback_app_auth import AppAuthError, OidcWebClient

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

oidc = OidcWebClient(os.environ["OPENBACK_ISSUER"], os.environ["OPENBACK_CLIENT_ID"], os.environ["OPENBACK_CLIENT_SECRET"],
                     redirect_uri="http://localhost:5000/callback")

TOKENS: dict = {}   # server-side token store: session id -> TokenSet.to_dict()


@app.get("/")
def home():
    user = session.get("user")
    if not user:
        return '<a href="/login">Sign in</a> · <a href="/login?provider=google">Sign in with Google</a>'
    return f"Hello {user.get('name') or user.get('email')} · <a href='/userinfo'>userinfo</a> · <a href='/logout'>Sign out</a>"


@app.get("/login")
def login():
    req = oidc.authorization_url(provider=request.args.get("provider"), screen_hint=request.args.get("screen_hint"))
    session["oidc"] = req.to_dict()   # state, nonce, PKCE verifier: needed by the callback
    return redirect(req.url)


@app.get("/callback")
def callback():
    transaction = session.pop("oidc", None)
    if not transaction:
        abort(400, "No sign-in in progress")
    try:
        tokens = oidc.handle_callback(request.args, transaction)
    except AppAuthError as err:
        abort(400, f"Sign-in failed: {err.code}")
    sid = secrets.token_urlsafe(24)
    TOKENS[sid] = tokens.to_dict()
    claims = tokens.id_token_claims or {}
    session.clear()
    session["sid"] = sid
    session["user"] = {k: claims.get(k) for k in ("sub", "email", "name", "org_id", "roles")}
    return redirect(url_for("home"))


@app.get("/userinfo")
def userinfo():
    stored = TOKENS.get(session.get("sid", ""))
    if not stored:
        return redirect(url_for("login"))
    try:
        return oidc.userinfo(stored["access_token"])
    except AppAuthError:
        renewed = oidc.refresh(stored["refresh_token"])        # rotation: keep the NEW refresh token
        TOKENS[session["sid"]] = {**renewed.to_dict(), "id_token": stored.get("id_token")}
        return oidc.userinfo(renewed.access_token)


@app.get("/logout")
def logout():
    stored = TOKENS.pop(session.get("sid", ""), None) or {}
    session.clear()
    if stored.get("refresh_token"):
        try:
            oidc.revoke(stored["refresh_token"])
        except AppAuthError:
            pass
    return redirect(oidc.logout_url(id_token_hint=stored.get("id_token"), post_logout_redirect_uri="http://localhost:5000/"))
