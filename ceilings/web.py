import http.client
import json
import os
import socket
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from .auth import LoginRequest, LoginVerification, Role
from .security import utcnow, verify_access

router = APIRouter()
ACCESS = "ceilings_access"
REFRESH = "ceilings_refresh"
COOKIE_OPTIONS = {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}
STATIC = Path(__file__).with_name("browser")
AUTH_HOST = "auth.ceilings.test"


async def browser_origin(request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if request.headers.getlist("origin") != [os.environ["WEB_ORIGIN"]]:
            return JSONResponse({"detail": "invalid_origin"}, status_code=403, headers={"Cache-Control": "no-store"})
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def call_auth(action, body, failure="auth_unavailable"):
    connection = http.client.HTTPConnection(AUTH_HOST, timeout=7)
    try:
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.settimeout(7)
        connection.sock.connect("/sockets/web-out.sock")
        connection.request("POST", f"/internal/auth/{action}", json.dumps(body),
                           {"Content-Type": "application/json", "Host": AUTH_HOST})
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        if status in (200, 401, 403, 422, 429):
            return status, json.loads(payload)
        if status == 204:
            return status, {}
    except (OSError, ValueError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    raise HTTPException(503, failure)


def require_success(status, payload):
    if status >= 400:
        raise HTTPException(status, payload.get("detail", "request_failed"))


def set_tokens(response, pair):
    now = int(utcnow().timestamp())
    response.set_cookie(ACCESS, pair["access"], max_age=max(0, pair["access_expiry"] - now), **COOKIE_OPTIONS)
    response.set_cookie(REFRESH, pair["refresh"], max_age=max(0, pair["session_expiry"] - now), **COOKIE_OPTIONS)


def clear_tokens(response):
    response.delete_cookie(ACCESS, **COOKIE_OPTIONS)
    response.delete_cookie(REFRESH, **COOKIE_OPTIONS)


@router.get("/", include_in_schema=False)
@router.get("/admin", include_in_schema=False)
def login_page():
    return FileResponse(STATIC / "login.html", media_type="text/html")


@router.get("/login.js", include_in_schema=False)
def scripts():
    return FileResponse(STATIC / "login.js", media_type="text/javascript")


@router.post("/auth/code")
def request_email_code(body: LoginRequest):
    status, payload = call_auth("code", body.model_dump())
    require_success(status, payload)
    return payload


@router.post("/auth/verify")
def verify_email_code(body: LoginVerification, response: Response):
    status, pair = call_auth("verify", body.model_dump())
    require_success(status, pair)
    set_tokens(response, pair)
    return {"role": body.role}


@router.get("/auth/session")
def session(role: Role, request: Request):
    token = request.cookies.get(ACCESS)
    claims = verify_access(token) if token else None
    if claims is None:
        raise HTTPException(401, "refresh_available" if request.cookies.get(REFRESH) else "login_required")
    if claims["role"] != role:
        raise HTTPException(403, "wrong_role")
    if role == "admin":
        status, payload = call_auth("session", {key: claims[key] for key in ("sid", "sub", "role")})
        require_success(status, payload)
    return {"email": claims["email"], "role": role, "expires_at": claims["exp"]}


@router.post("/auth/refresh")
def refresh(role: Role, request: Request, response: Response):
    token = request.cookies.get(REFRESH)
    if not token:
        raise HTTPException(401, "login_required")
    status, pair = call_auth("refresh", {"refresh": token, "role": role})
    if status == 401:
        response.status_code = 401
        clear_tokens(response)
        return {"detail": "session_denied"}
    require_success(status, pair)
    set_tokens(response, pair)
    return {"role": role}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token = request.cookies.get(REFRESH)
    if not token:
        raise HTTPException(401, "unknown_session")
    status, payload = call_auth("logout", {"refresh": token}, failure="logout_unconfirmed")
    require_success(status, payload)
    clear_tokens(response)
