"""FastAPI: routes protected by the pool's access tokens.

    pip install "openback-app-auth-python[fastapi]" uvicorn
    set OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main
    set OPENBACK_CLIENT_IDS=uapp_web...,uapp_mobile...      (the apps whose users may call this API)
    uvicorn fastapi_protected_route:app --reload

    curl -H "Authorization: Bearer <access token>" http://127.0.0.1:8000/me
"""
import os

from fastapi import Depends, FastAPI

from openback_app_auth import AppUser, TokenVerifier
from openback_app_auth.fastapi import install_error_handler, optional_app_user, require_app_user

verifier = TokenVerifier(os.environ["OPENBACK_ISSUER"], os.environ["OPENBACK_CLIENT_IDS"].split(","))

app = FastAPI(title="Orders API")
install_error_handler(app)   # 401/403 bodies exactly {"error": "..."}

signed_in = require_app_user(verifier)
admin = require_app_user(verifier, require_roles=["admin", "owner"], require_verified_email=True)
reader = require_app_user(verifier, require_permissions=["orders.read"])


@app.get("/public")
async def public(user=Depends(optional_app_user(verifier))):
    return {"hello": user.email if user else "guest"}


@app.get("/me")
async def me(user: AppUser = Depends(signed_in)):
    return {"id": user.id, "email": user.email, "org": user.org_id, "roles": user.roles}


@app.get("/orders")
async def orders(user: AppUser = Depends(reader)):
    return {"org": user.org_id, "orders": []}


@app.delete("/orders/{order_id}")
async def delete_order(order_id: str, user: AppUser = Depends(admin)):
    return {"deleted": order_id, "by": user.id}
