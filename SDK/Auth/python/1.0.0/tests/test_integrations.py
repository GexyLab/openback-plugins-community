"""FastAPI, Flask and Django integrations (skipped when the framework is not installed)."""
import pytest

from conftest import CLIENT_ID, ISSUER, FakePool
from openback_app_auth import TokenVerifier


def verifier_for(pool: FakePool) -> TokenVerifier:
    return TokenVerifier(ISSUER, CLIENT_ID, http_client=pool.http(), async_http_client=pool.ahttp())


def cases(pool: FakePool):
    """(headers, expected status, expected error) for a route requiring the role "admin"."""
    return [
        ({}, 401, "invalid_token"),
        ({"Authorization": "Basic abc"}, 401, "invalid_token"),
        ({"Authorization": "Bearer not-a-token"}, 401, "invalid_token"),
        ({"Authorization": "Bearer " + pool.access_token(aud="uapp_other")}, 401, "invalid_token"),
        ({"Authorization": "Bearer " + pool.access_token()}, 403, "insufficient_scope"),               # role member
        ({"Authorization": "Bearer " + pool.access_token(roles=["admin"], anon=True)}, 403, "insufficient_scope"),
        ({"Authorization": "bearer " + pool.access_token(roles=["admin"])}, 200, None),
    ]


def check(response_status, body, headers, status, error):
    assert response_status == status
    if error:
        assert body == {"error": error}
        assert headers.get("WWW-Authenticate") == f'Bearer error="{error}"'


# --- FastAPI -------------------------------------------------------------------------------------------------------------

def test_fastapi(pool):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from openback_app_auth import AppUser
    from openback_app_auth.fastapi import install_error_handler, optional_app_user, require_app_user

    verifier = verifier_for(pool)
    app = fastapi.FastAPI()
    install_error_handler(app)

    @app.get("/admin")
    async def admin(user: AppUser = fastapi.Depends(require_app_user(verifier, require_roles=["admin"]))):
        return {"id": user.id}

    @app.get("/maybe")
    async def maybe(user=fastapi.Depends(optional_app_user(verifier))):
        return {"id": user.id if user else None}

    with TestClient(app) as http:
        for headers, status, error in cases(pool):
            r = http.get("/admin", headers=headers)
            check(r.status_code, r.json(), r.headers, status, error)
        assert http.get("/admin", headers={"Authorization": "Bearer " + pool.access_token(roles=["admin"])}).json() == {"id": "usr_1"}
        assert http.get("/maybe").json() == {"id": None}
        assert http.get("/maybe", headers={"Authorization": "Bearer " + pool.access_token()}).json() == {"id": "usr_1"}
        assert http.get("/maybe", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_fastapi_default_handler(pool):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from openback_app_auth.fastapi import require_app_user

    app = fastapi.FastAPI()

    @app.get("/x", dependencies=[fastapi.Depends(require_app_user(verifier_for(pool)))])
    async def x():
        return {}

    with TestClient(app) as http:
        r = http.get("/x")
        assert r.status_code == 401 and r.json() == {"detail": {"error": "invalid_token"}}
        assert r.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


# --- Flask ---------------------------------------------------------------------------------------------------------------

def test_flask(pool):
    flask = pytest.importorskip("flask")
    from openback_app_auth.flask import current_app_user, require_app_user

    verifier = verifier_for(pool)
    app = flask.Flask(__name__)

    @app.get("/admin")
    @require_app_user(verifier, require_roles=["admin"], require_verified_email=True)
    def admin():
        return {"id": flask.g.app_user.id, "same": current_app_user() is flask.g.app_user}

    http = app.test_client()
    for headers, status, error in cases(pool):
        r = http.get("/admin", headers=headers)
        check(r.status_code, r.get_json(), r.headers, status, error)
    r = http.get("/admin", headers={"Authorization": "Bearer " + pool.access_token(roles=["admin"])})
    assert r.get_json() == {"id": "usr_1", "same": True}
    r = http.get("/admin", headers={"Authorization": "Bearer " + pool.access_token(roles=["admin"], email_verified=False)})
    assert r.status_code == 403


# --- Django --------------------------------------------------------------------------------------------------------------

def test_django(pool):
    pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=False, SECRET_KEY="test", ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__,
                           OPENBACK_APP_AUTH=verifier_for(pool))
        import django
        django.setup()
    else:  # pragma: no cover
        settings.OPENBACK_APP_AUTH = verifier_for(pool)

    import json

    from django.http import JsonResponse
    from django.test import RequestFactory

    from openback_app_auth.django import AppAuthMiddleware, require_app_user, reset_verifier

    reset_verifier()

    @require_app_user(require_permissions=["orders.read"], require_roles=["admin"])
    def admin(request):
        return JsonResponse({"id": request.app_user.id})

    @require_app_user
    def bare(request):
        return JsonResponse({"id": request.app_user.id})

    factory = RequestFactory()
    middleware = AppAuthMiddleware(admin)
    for headers, status, error in cases(pool):
        request = factory.get("/admin", headers=headers)
        response = middleware(request)
        body = json.loads(response.content)
        check(response.status_code, body, {"WWW-Authenticate": response.get("WWW-Authenticate")}, status, error)

    # without the middleware the decorator verifies by itself
    ok = bare(factory.get("/bare", headers={"Authorization": "Bearer " + pool.access_token()}))
    assert ok.status_code == 200 and json.loads(ok.content) == {"id": "usr_1"}
    refused = bare(factory.get("/bare"))
    assert refused.status_code == 401 and refused["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    # the middleware alone never refuses
    seen = {}

    def view(request):
        seen["user"] = request.app_user
        return JsonResponse({})

    assert AppAuthMiddleware(view)(factory.get("/", headers={"Authorization": "Bearer junk"})).status_code == 200
    assert seen["user"] is None


urlpatterns: list = []
