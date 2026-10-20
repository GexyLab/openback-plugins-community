"""CLI: sign in with email + password (with the two-step branches), then call an API as the user.

    pip install openback-app-auth-python
    set OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main
    set OPENBACK_CLIENT_ID=uapp_...            (an app of kind "native" in the pool's Apps tab)
    python cli_password_signin.py [--api https://api.example.com/orders] [--sign-out]

The session is kept in ~/.openback-example.session.json (mode 0600), so the next run is already signed in.
"""
import argparse
import getpass
import os
import sys

from openback_app_auth import AppAuthError, Client, FileStorage


def complete(auth: Client, outcome, email: str):
    """Follow the sign-in outcome until signed in (or give up)."""
    while outcome.status != "ok":
        if outcome.status == "mfa_required":
            outcome = auth.verify_mfa(outcome.mfa_token, input("Authenticator (or recovery) code: ").strip())
        elif outcome.status == "mfa_enroll_required":
            enrollment = auth.enroll_mfa(outcome.mfa_token)
            print("Two-step verification is required. Add this account to your authenticator app:")
            print("  ", enrollment.otpauth_uri)   # shown to the user on purpose: it is their own secret
            confirmation = auth.confirm_mfa(input("Code from the app: ").strip(), outcome.mfa_token)
            print("Recovery codes (store them safely, shown once):", ", ".join(confirmation.recovery_codes))
            outcome = confirmation.outcome
        elif outcome.status == "password_change_required":
            new_password = getpass.getpass("You must choose a new password: ")
            auth.change_forced_password(outcome.change_token, new_password)
            outcome = auth.sign_in_with_password(email, new_password)
        elif outcome.status == "verification_required":
            sys.exit("Verify your email address first (check your inbox), then run again.")
        else:
            sys.exit(f"Unexpected sign-in step: {outcome.status}")
    return outcome


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", help="an API URL to call with the user's token")
    parser.add_argument("--sign-out", action="store_true")
    args = parser.parse_args()

    issuer = os.environ.get("OPENBACK_ISSUER") or sys.exit("set OPENBACK_ISSUER")
    client_id = os.environ.get("OPENBACK_CLIENT_ID") or sys.exit("set OPENBACK_CLIENT_ID")
    storage = FileStorage(os.path.expanduser("~/.openback-example.session.json"))

    with Client(issuer, client_id, storage=storage) as auth:
        if args.sign_out:
            auth.sign_out()
            print("Signed out.")
            return
        if not auth.is_signed_in:
            email = input("Email: ").strip()
            try:
                outcome = auth.sign_in_with_password(email, getpass.getpass("Password: "))
                complete(auth, outcome, email)
            except AppAuthError as err:
                sys.exit(f"Sign-in failed ({err.code}): {err.message}")

        user = auth.me()
        print(f"Signed in as {user.display_name or user.email} ({user.id}), roles: {', '.join(user.roles) or '-'}")

        if args.api:
            response = auth.request("GET", args.api)
            print(response.status_code, response.text[:500])


if __name__ == "__main__":
    main()
