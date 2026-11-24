import hashlib
import hmac
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from email_validator import EmailNotValidError
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from .broker import publish_code
from .email_address import UnsupportedLocalPart, login_address
from .security import issue_access, utcnow

router = APIRouter(prefix="/internal/auth")
Role = Literal["client", "admin"]
CODE_LIFETIME = timedelta(minutes=10)
LATEST_CODE = """SELECT id,digest,issued_at,expires_at,attempts,consumed_at,cancelled_at
FROM app.login_codes WHERE email=:email AND purpose=:role ORDER BY issued_at DESC LIMIT 1"""
ACCOUNT = "SELECT id FROM app.accounts WHERE email=:email AND role=:role"
SESSION = """SELECT s.id,s.account_id,s.role,s.expires_at,s.revoked_at,a.email,a.role AS account_role
FROM app.sessions s JOIN app.accounts a ON a.id=s.account_id WHERE s.id=:sid"""


class LoginRequest(BaseModel):
    email: str = Field(max_length=320)
    role: Role


class LoginVerification(LoginRequest):
    code: str = Field(pattern=r"^[0-9]{6}$")


class RefreshRequest(BaseModel):
    refresh: str = Field(min_length=1, max_length=128)
    role: Role


class LogoutRequest(BaseModel):
    refresh: str = Field(min_length=1, max_length=128)


class SessionRequest(BaseModel):
    sid: UUID
    sub: UUID
    role: Role


def validate_login_address(value):
    try:
        return login_address(value)
    except UnsupportedLocalPart:
        raise HTTPException(422, "unsupported_email_local_part") from None
    except EmailNotValidError:
        raise HTTPException(422, "invalid_email") from None


def code_digest(code_id, code):
    key = Path("/run/secrets/login_code_key").read_bytes().strip()
    return hmac.digest(key, f"{code_id}:{code}".encode(), "sha256")


def lock_login(connection, email):
    connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                       {"scope": f"login:{email}"})


def create_code(engine, email, role, delivery_email):
    identity = {"email": email, "role": role}
    with engine.begin() as connection:
        lock_login(connection, email)
        now = utcnow()
        if role == "admin" and connection.scalar(text(ACCOUNT), identity) is None:
            return "accepted", None
        latest = connection.execute(text(LATEST_CODE), identity).one_or_none()
        if latest and now < latest.issued_at + timedelta(minutes=1):
            return "limited", None
        total = connection.scalar(text("""SELECT count(*) FROM app.login_codes
            WHERE email=:email AND purpose=:role AND issued_at > :since"""),
                                  {**identity, "since": now - timedelta(hours=1)})
        if total >= 5:
            return "limited", None
        nearby = connection.execute(text("""SELECT id,digest FROM app.login_codes
            WHERE email=:email AND expires_at>:now"""), {"email": email, "now": now}).all()
        if latest and all(record.id != latest.id for record in nearby):
            nearby.append(latest)
        code_id = uuid4()
        code = f"{secrets.randbelow(1_000_000):06d}"
        while any(hmac.compare_digest(record.digest, code_digest(record.id, code)) for record in nearby):
            code = f"{secrets.randbelow(1_000_000):06d}"
        if latest and latest.consumed_at is None and latest.cancelled_at is None:
            connection.execute(text("UPDATE app.login_codes SET cancelled_at=:now WHERE id=:id"),
                               {"now": now, "id": latest.id})
        expires = now + CODE_LIFETIME
        connection.execute(text("""INSERT INTO app.login_codes (id,email,purpose,digest,issued_at,expires_at)
            VALUES (:id,:email,:role,:digest,:now,:expires)"""),
                           {**identity, "id": code_id, "digest": code_digest(code_id, code), "now": now, "expires": expires})
    return "accepted", {"id": str(code_id), "email": delivery_email, "role": role, "code": code,
                        "expires_at": expires.isoformat()}


def refresh_digest(token):
    return hashlib.sha256(token.encode()).digest()


def issue_pair(connection, sid, account_id, role, email, expires):
    refresh = secrets.token_urlsafe(32)
    connection.execute(text("INSERT INTO app.refresh_tokens (digest,session_id) VALUES (:digest,:sid)"),
                       {"digest": refresh_digest(refresh), "sid": sid})
    access, access_expiry = issue_access(sid, account_id, role, email, expires)
    return {"access": access, "access_expiry": access_expiry, "refresh": refresh,
            "session_expiry": int(expires.timestamp())}


def verify_code(engine, email, role, code):
    identity = {"email": email, "role": role}
    with engine.begin() as connection:
        lock_login(connection, email)
        latest = connection.execute(text(LATEST_CODE), identity).one_or_none()
        now = utcnow()
        if (latest is None or latest.expires_at <= now or latest.attempts >= 5
                or latest.cancelled_at is not None or latest.consumed_at is not None):
            return None
        if not hmac.compare_digest(latest.digest, code_digest(latest.id, code)):
            connection.execute(text("UPDATE app.login_codes SET attempts=attempts+1 WHERE id=:id"), {"id": latest.id})
            return None
        account = connection.scalar(text(ACCOUNT), identity)
        if account is None:
            if role == "admin":
                return None
            account = uuid4()
            connection.execute(text("INSERT INTO app.accounts (id,email,role) VALUES (:id,:email,:role)"),
                               {**identity, "id": account})
        connection.execute(text("UPDATE app.login_codes SET consumed_at=:now WHERE id=:id"),
                           {"now": now, "id": latest.id})
        sid = uuid4()
        expires = now + (timedelta(hours=8) if role == "admin" else timedelta(days=30))
        connection.execute(text("INSERT INTO app.sessions (id,account_id,role,expires_at) VALUES (:sid,:account,:role,:expires)"),
                           {"sid": sid, "account": account, "role": role, "expires": expires})
        return issue_pair(connection, sid, account, role, email, expires)


def valid_session(session, now):
    return session and session.revoked_at is None and session.expires_at > now and session.role == session.account_role


def revoke(connection, sid, now):
    connection.execute(text("UPDATE app.sessions SET revoked_at=COALESCE(revoked_at,:now) WHERE id=:sid"),
                       {"sid": sid, "now": now})


def update_session(engine, refresh, role=None):
    digest = refresh_digest(refresh)
    with engine.begin() as connection:
        sid = connection.scalar(text("SELECT session_id FROM app.refresh_tokens WHERE digest=:digest"), {"digest": digest})
        if sid is None:
            return "denied", None
        session = connection.execute(text(SESSION + " FOR UPDATE OF s"), {"sid": sid}).one_or_none()
        if session is None:
            return "denied", None
        now = utcnow()
        if role is None:
            revoke(connection, sid, now)
            return "ended", None
        used = connection.scalar(text("SELECT used_at FROM app.refresh_tokens WHERE digest=:digest"), {"digest": digest})
        if used is not None:
            revoke(connection, sid, now)
            return "denied", None
        if not valid_session(session, now):
            return "denied", None
        if role != session.role:
            return "wrong_role", None
        connection.execute(text("UPDATE app.refresh_tokens SET used_at=:now WHERE digest=:digest"),
                           {"now": now, "digest": digest})
        return "updated", issue_pair(connection, sid, session.account_id, role, session.email, session.expires_at)


@router.post("/code")
async def request_code(body: LoginRequest, request: Request):
    address = validate_login_address(body.email)
    result, command = await run_in_threadpool(create_code, request.app.state.database, address.normalized.lower(),
                                               body.role, address.ascii_email.lower())
    if result == "limited":
        raise HTTPException(429, "code_limit")
    return {"publication_confirmed": await publish_code(command) if command is not None else True}


@router.post("/verify")
def confirm_code(body: LoginVerification, request: Request):
    email = validate_login_address(body.email).normalized.lower()
    pair = verify_code(request.app.state.database, email, body.role, body.code)
    if pair is None:
        raise HTTPException(401, "invalid_code")
    return pair


@router.post("/refresh")
def refresh_session(body: RefreshRequest, request: Request):
    result, pair = update_session(request.app.state.database, body.refresh, body.role)
    if result == "wrong_role":
        raise HTTPException(403, "wrong_role")
    if result != "updated":
        raise HTTPException(401, "session_denied")
    return pair


@router.post("/logout", status_code=204)
def logout(body: LogoutRequest, request: Request):
    result, _ = update_session(request.app.state.database, body.refresh)
    if result != "ended":
        raise HTTPException(401, "unknown_session")
    return Response(status_code=204)


@router.post("/session", status_code=204)
def validate_session(body: SessionRequest, request: Request):
    with request.app.state.database.connect() as connection:
        session = connection.execute(text(SESSION), {"sid": body.sid}).one_or_none()
    if not valid_session(session, utcnow()) or body.role != session.role or body.sub != session.account_id:
        raise HTTPException(401, "session_denied")
    return Response(status_code=204)
