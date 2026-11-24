"""Prepare and run the local Ceilings Docker Compose environment."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DATABASES = ("auth", "order", "noti")
BROWSER_HOSTS = ("app.ceilings.test", "mailpit.ceilings.test")
STREAMS = (
    ("login", "auth_publisher", "noti_codes"),
    ("orders", "order_publisher", "noti_orders"),
)


def run(argv, env):
    subprocess.run(argv, cwd=ROOT, env=env, check=True)


def compose(args, env):
    run(["docker", "compose", *args], env)


def password(directory, name):
    path = directory / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_urlsafe(32).encode("ascii"))
    return path.read_text().strip()


def rabbit_user(directory, name):
    salt = secrets.token_bytes(4)
    digest = hashlib.sha256(salt + password(directory, f"rabbit_{name}").encode()).digest()
    return {"name": name, "password_hash": base64.b64encode(salt + digest).decode(),
            "hashing_algorithm": "rabbit_password_hashing_sha256", "tags": []}


def prepare_broker(directory):
    target = directory / "rabbit_definitions.json"
    if target.exists():
        return
    vhost = "ceilings"
    definitions = {"vhosts": [{"name": vhost}], "users": [], "permissions": [],
                   "exchanges": [], "queues": [], "bindings": []}
    for flow, producer, consumer in STREAMS:
        exchange = f"ceilings.{flow}"
        queue = f"ceilings.{flow}.mail"
        definitions["users"].extend(rabbit_user(directory, name) for name in (producer, consumer))
        definitions["permissions"].extend([
            {"user": producer, "vhost": vhost, "configure": "^$", "write": f"^{re.escape(exchange)}$", "read": "^$"},
            {"user": consumer, "vhost": vhost, "configure": "^$", "write": "^$", "read": f"^{re.escape(queue)}$"},
        ])
        definitions["exchanges"].append({"name": exchange, "vhost": vhost, "type": "direct", "durable": True,
                                         "auto_delete": False, "internal": False, "arguments": {}})
        definitions["queues"].append({"name": queue, "vhost": vhost, "durable": True,
                                      "auto_delete": False, "arguments": {}})
        definitions["bindings"].append({"source": exchange, "vhost": vhost, "destination": queue,
                                         "destination_type": "queue", "routing_key": "mail", "arguments": {}})
    target.write_text(json.dumps(definitions, indent=2), encoding="utf-8")


def prepare(directory, env, mkcert):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    protected = directory / "secrets"
    protected.mkdir(mode=0o700, exist_ok=True)
    password(protected, "ca_password")
    password(protected, "operator_password")
    password(protected, "login_code_key")
    for service in DATABASES:
        for role in ("bootstrap", "app", "migrator"):
            password(protected, f"{service}_{role}")
    prepare_broker(protected)

    browser = directory / "browser"
    browser.mkdir(mode=0o700, exist_ok=True)
    cert, key = browser / "cert.pem", browser / "key.pem"
    run([mkcert, "-install"], env)
    if not cert.is_file() or not key.is_file():
        run([mkcert, "-cert-file", str(cert), "-key-file", str(key), *BROWSER_HOSTS], env)
        key.chmod(0o444)


def start(directory, env, recover=False):
    protected = directory / "secrets"
    if not (protected / "ca_password").is_file():
        raise FileNotFoundError(2, "Run prepare first", str(protected / "ca_password"))
    password(protected, "operator_password")
    password(protected, "login_code_key")
    for subdirectory in ("private", "public"):
        (directory / "jwt" / subdirectory).mkdir(mode=0o700, parents=True, exist_ok=True)
    compose(["build", "web", "pki-operator"], env)
    compose(["run", "--rm", "--no-deps", "jwt-keys"], env)
    if recover:
        compose(["stop"], env)
    compose(["run", "--rm", "--no-deps", "pki-operator", "init"], env)
    compose(["up", "-d", "ca"], env)
    compose(["run", "--rm", "--no-deps", "pki-operator", "recover-expired" if recover else "issue-missing"], env)
    compose(["up", "-d", "--wait", "--wait-timeout", "100", "pg-auth", "pg-order", "pg-noti", "rabbitmq", "mailpit"], env)
    for service in DATABASES:
        compose(["run", "--rm", "--no-deps", f"migrate-{service}"], env)
    compose(["up", "-d", "--wait", "--wait-timeout", "60"], env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(os.environ.get("CEILINGS_LOCAL_DIR", Path.home() / ".ceilings-local")))
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("prepare").add_argument("--mkcert", default="mkcert")
    commands.add_parser("up")
    commands.add_parser("recover")
    commands.add_parser("compose").add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    directory = args.directory.expanduser().resolve()
    if directory.is_relative_to(ROOT):
        parser.error("Choose a local data directory outside the repository")
    env = {**os.environ, "CEILINGS_LOCAL_DIR": directory.as_posix(), "CAROOT": str(directory / "browser-ca")}
    try:
        if args.action == "prepare":
            prepare(directory, env, args.mkcert)
        elif args.action in ("up", "recover"):
            start(directory, env, recover=args.action == "recover")
        else:
            compose(args.arguments, env)
    except subprocess.CalledProcessError as error:
        parser.exit(error.returncode)
    except FileNotFoundError as error:
        parser.exit(1, f"Missing executable or file: {error.filename}\n")


if __name__ == "__main__":
    main()
