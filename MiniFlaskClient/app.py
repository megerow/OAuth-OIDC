"""MiniFlaskClient: signs a user in through the identity provider (authorization code + PKCE),
then calls the protected API's endpoints with the resulting access token and reports what happened."""

import base64
import hashlib
import os
import secrets
import threading
import time
from urllib.parse import urlencode

import jwt
import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

IDP_BASE_URL = os.environ.get("IDP_BASE_URL", "http://localhost:5121").rstrip("/")
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:5062").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "my_learning_client_app")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8080/callback/")
PORT = int(os.environ.get("PORT", "8080"))
SCOPE = os.environ.get("SCOPE", "openid profile offline_access")  # offline_access is what asks the IdP for a refresh token
REFRESH_MARGIN_SECONDS = int(os.environ.get("REFRESH_MARGIN_SECONDS", "60"))  # renew this long before the access token expires
HTTP_TIMEOUT = 10

# The endpoints to try, and who is expected to be allowed in
API_ENDPOINTS = [
    ("/api/public", "Anyone"),
    ("/api/admin-dashboard", "Role: Admin"),
    ("/api/billing", "Role: BillingManager"),
]

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
# localhost cookies are shared across ports, so give ours a name no other local app is likely to use
app.config.update(SESSION_COOKIE_NAME="miniflask_session", SESSION_COOKIE_SAMESITE="Lax")

# Tokens stay on the server. The browser cookie only carries a random session id, because a token is too big to keep in a cookie.
SIGNED_IN = {}

_discovery = None
_jwks_client = None
_refresh_lock = threading.Lock()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def discovery() -> dict:
    """Finds the IdP's endpoints from its discovery document, so pointing at another IdP is a config change."""
    global _discovery
    if _discovery is None:
        response = requests.get(f"{IDP_BASE_URL}/.well-known/openid-configuration", timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        _discovery = response.json()
    return _discovery


def validate_id_token(id_token: str, meta: dict) -> dict:
    """Checks the signature against the IdP's published keys, plus issuer, audience and expiry."""
    global _jwks_client
    if _jwks_client is None or _jwks_client.uri != meta["jwks_uri"]:
        _jwks_client = jwt.PyJWKClient(meta["jwks_uri"])

    signing_key = _jwks_client.get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=meta["issuer"],
        leeway=10,
        options={"require": ["exp", "iss", "aud", "sub"]},
    )


def current_user():
    """The signed-in user's server-side record, or None.

    An access token that is about to expire is renewed with the refresh token first. If the IdP refuses the refresh
    and the access token has run out, the user is signed out."""
    sid = session.get("sid")
    record = SIGNED_IN.get(sid)
    if not record:
        return None

    if record["expires_at"] - time.time() <= REFRESH_MARGIN_SECONDS:
        refreshed = refresh_tokens(record)
        if not refreshed and record["expires_at"] <= time.time():
            end_session(sid)
            return None
    return record


def end_session(sid):
    SIGNED_IN.pop(sid, None)
    session.pop("sid", None)


def refresh_tokens(record: dict, force: bool = False) -> bool:
    """Trades the refresh token for new tokens. The IdP rotates refresh tokens, so the new one replaces the old.

    Returns False when there is no refresh token, the IdP is unreachable, or the IdP refuses it (expired, revoked or
    replayed). One lock covers all sessions: sending the same refresh token twice at once would look like a replay
    and the IdP would revoke it."""
    with _refresh_lock:
        if not record.get("refresh_token"):
            return False
        # Another request may have refreshed while this one waited for the lock
        if not force and record["expires_at"] - time.time() > REFRESH_MARGIN_SECONDS:
            return True

        try:
            meta = discovery()
            response = requests.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": record["refresh_token"],
                    "client_id": CLIENT_ID,
                    "scope": SCOPE,
                },
                timeout=HTTP_TIMEOUT,
            )
            if not response.ok:
                app.logger.warning("Refresh refused: %s %s", response.status_code, response.text[:200])
                return False

            tokens = response.json()
            if "id_token" in tokens:
                record["claims"] = validate_id_token(tokens["id_token"], meta)
        except (requests.RequestException, jwt.PyJWTError, ValueError) as ex:
            app.logger.warning("Refresh failed: %s: %s", type(ex).__name__, ex)
            return False

        record["access_token"] = tokens["access_token"]
        record["refresh_token"] = tokens.get("refresh_token", record["refresh_token"])
        record["expires_at"] = time.time() + int(tokens.get("expires_in", 3600))
        record["refresh_count"] += 1
        record["last_refreshed"] = time.time()
        app.logger.info("Access token refreshed (%d so far)", record["refresh_count"])
        return True


def error_page(title: str, detail: str, status: int = 400):
    return render_template("error.html", title=title, detail=detail), status


def call_api(path: str, expected: str, access_token: str) -> dict:
    result = {"path": path, "expected": expected, "status": None, "verdict": "", "body": ""}
    try:
        response = requests.get(f"{API_BASE_URL}{path}", headers={"Authorization": f"Bearer {access_token}"}, timeout=HTTP_TIMEOUT)
    except requests.RequestException as ex:
        result["verdict"] = f"Could not reach the API at {API_BASE_URL} ({type(ex).__name__})"
        return result

    result["status"] = response.status_code
    result["body"] = response.text[:500]
    result["verdict"] = {
        200: "Allowed",
        401: "Rejected: the token is missing, expired, or not accepted by the API",
        403: "Forbidden: signed in, but the token does not carry the required role",
    }.get(response.status_code, f"Unexpected response ({response.reason})")
    if response.status_code == 401 and response.headers.get("WWW-Authenticate"):
        result["body"] = response.headers["WWW-Authenticate"]
    return result


def run_checks(record: dict) -> list:
    results = [call_api(path, expected, record["access_token"]) for path, expected in API_ENDPOINTS]
    for r in results:
        app.logger.info("%s (%s) -> %s %s", r["path"], r["expected"], r["status"], r["verdict"])
    return results


@app.get("/")
def home():
    return render_template("index.html", user=current_user(), idp=IDP_BASE_URL, api=API_BASE_URL, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI, notice=request.args.get("notice"))


@app.get("/login")
def login():
    try:
        meta = discovery()
    except requests.RequestException as ex:
        return error_page("Cannot reach the identity provider", f"Tried {IDP_BASE_URL}: {ex}", 502)

    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = b64url(secrets.token_bytes(16))
    session["oauth"] = {"state": state, "verifier": verifier}

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return redirect(f"{meta['authorization_endpoint']}?{urlencode(params)}")


@app.get("/callback/")
def callback():
    saved = session.pop("oauth", None)

    if request.args.get("error"):
        return error_page("The identity provider returned an error", f"{request.args['error']}: {request.args.get('error_description', '')}")

    # The state we sent must come back unchanged, otherwise the response was not for a login we started
    if not saved or not secrets.compare_digest(request.args.get("state", ""), saved["state"]):
        return error_page("Sign-in could not be verified", "The state value did not match. Start again from the home page.")

    code = request.args.get("code")
    if not code:
        return error_page("No authorization code", "The identity provider did not return a code.")

    try:
        meta = discovery()
        token_response = requests.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": saved["verifier"],
            },
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as ex:
        return error_page("Cannot reach the identity provider", str(ex), 502)

    if not token_response.ok:
        return error_page("Token request failed", f"{token_response.status_code}: {token_response.text[:500]}")

    tokens = token_response.json()
    try:
        claims = validate_id_token(tokens["id_token"], meta)
    except (jwt.PyJWTError, KeyError) as ex:
        return error_page("The ID token was not valid", f"{type(ex).__name__}: {ex}")

    sid = secrets.token_urlsafe(16)
    SIGNED_IN[sid] = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "claims": claims,
        "expires_at": time.time() + int(tokens.get("expires_in", 3600)),
        "refresh_count": 0,
        "last_refreshed": None,
    }
    session["sid"] = sid
    return redirect(url_for("results"))


@app.get("/results")
def results():
    record = current_user()
    if not record:
        return redirect(url_for("home"))
    return render_template(
        "results.html",
        claims=record["claims"],
        results=run_checks(record),
        expires_at=time.strftime("%H:%M:%S", time.localtime(record["expires_at"])),
        has_refresh_token=bool(record["refresh_token"]),
        refresh_count=record["refresh_count"],
        last_refreshed=time.strftime("%H:%M:%S", time.localtime(record["last_refreshed"])) if record["last_refreshed"] else None,
        notice=request.args.get("notice"),
    )


@app.get("/results.json")
def results_json():
    record = current_user()
    if not record:
        return jsonify(error="not_signed_in"), 401
    return jsonify(
        user=record["claims"],
        results=run_checks(record),
        access_token_expires_at=int(record["expires_at"]),
        has_refresh_token=bool(record["refresh_token"]),
        refresh_count=record["refresh_count"],
    )


@app.post("/refresh")
def refresh_now():
    """Forces a refresh so the rotation can be seen. Sign-in cookies are SameSite=Lax, so other sites cannot post here."""
    sid = session.get("sid")
    record = SIGNED_IN.get(sid)
    if not record:
        return redirect(url_for("home"))
    if refresh_tokens(record, force=True):
        return redirect(url_for("results", notice="refreshed"))
    end_session(sid)
    return redirect(url_for("home", notice="session_ended"))


@app.get("/logout")
def logout():
    SIGNED_IN.pop(session.get("sid"), None)
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)
