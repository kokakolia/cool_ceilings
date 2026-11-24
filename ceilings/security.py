import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "ceilings-auth"
AUDIENCE = "ceilings-web"
ALGORITHM = "RS256"
PRIVATE_KEY = Path("/run/secrets/jwt_key")
PUBLIC_KEYS = Path("/run/jwt/jwks.json")


def utcnow():
    return datetime.now(UTC)


def key_id(public):
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:24]


def issue_access(session_id, account_id, role, email, session_expiry):
    key = serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(), password=None)
    now = utcnow()
    expires = min(now + timedelta(minutes=5), session_expiry)
    claims = {"sid": str(session_id), "sub": str(account_id), "role": role, "email": email,
              "iat": now, "exp": expires, "iss": ISSUER, "aud": AUDIENCE}
    token = jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": key_id(key.public_key())})
    return token, int(expires.timestamp())


def verify_access(token):
    try:
        header = jwt.get_unverified_header(token)
        if not isinstance(header.get("kid"), str) or header.get("alg") != ALGORITHM:
            return None
        keys = json.loads(PUBLIC_KEYS.read_text(encoding="ascii"))["keys"]
        key = next((jwk for jwk in keys if jwk["kid"] == header["kid"]), None)
        if key is None:
            return None
        claims = jwt.decode(token, jwt.PyJWK.from_dict(key).key, algorithms=[ALGORITHM],
                            audience=AUDIENCE, issuer=ISSUER,
                            options={"require": ["exp", "iat", "iss", "aud", "sub", "sid", "role", "email"]})
        UUID(claims["sub"])
        UUID(claims["sid"])
        return claims if claims["role"] in ("client", "admin") else None
    except (jwt.PyJWTError, ValueError, TypeError):
        return None


def write_key_file(path, payload):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as staged:
        staged.write(payload)
    temporary = Path(staged.name)
    try:
        temporary.chmod(0o444)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def bootstrap_keys(directory):
    private = directory / "private/key.pem"
    jwks_path = directory / "public/jwks.json"
    if private.exists():
        key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    else:
        if jwks_path.exists():
            raise ValueError("Restore the JWT signing key before starting Ceilings")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        write_key_file(private, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    public = key.public_key()
    kid = key_id(public)
    if jwks_path.exists():
        keys = json.loads(jwks_path.read_text(encoding="ascii"))["keys"]
        if all(item["kid"] != kid for item in keys):
            raise ValueError("Publish the current JWT public key before starting Ceilings")
        return
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public, as_dict=True)
    jwk.update(kid=kid, alg=ALGORITHM, use="sig")
    write_key_file(jwks_path, json.dumps({"keys": [jwk]}).encode("ascii"))
