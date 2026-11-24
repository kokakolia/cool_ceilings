import argparse
import asyncio
import json
import logging
import os
import socket
from pathlib import Path
from uuid import uuid4

import uvicorn
from alembic import command
from alembic.config import Config
from email_validator import EmailNotValidError
from sqlalchemy import text

from .db import DATABASES, database_engine, database_state
from .email_address import login_address


def migrate(service):
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    config.set_main_option("version_locations", str(Path(__file__).parent / "migrations" / service))
    engine = database_engine(service, migrate=True)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.execute(text("REVOKE INSERT, UPDATE, DELETE ON app.alembic_version FROM app_user"))
        connection.commit()
    engine.dispose()


def create_first_admin(email):
    email = login_address(email).normalized.lower()
    engine = database_engine("auth")
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(493770561)"))
        existing = connection.execute(text(
            "SELECT id, email FROM app.accounts WHERE role = 'admin' ORDER BY created_at LIMIT 1"
        )).one_or_none()
        if existing:
            if existing.email != email:
                raise ValueError("First admin already exists with another email")
            return {"id": str(existing.id), "role": "admin", "created": False}
        account_id = uuid4()
        connection.execute(text(
            "INSERT INTO app.accounts (id, email, role) VALUES (:id, :email, 'admin')"
        ), {"id": account_id, "email": email})
    return {"id": str(account_id), "role": "admin", "created": True}


def serve(service):
    os.environ["CEILINGS_SERVICE"] = service
    if service == "noti":
        uvicorn.run("ceilings.asgi:app", host="0.0.0.0", port=8000, proxy_headers=False)
        return
    path = f"/sockets/{service}-in.sock"
    Path(path).unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX)
    with listener:
        listener.bind(path)
        os.chmod(path, 0o660)
        listener.listen(128)
        config = uvicorn.Config("ceilings.asgi:app", proxy_headers=False)
        uvicorn.Server(config).run(sockets=[listener])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("serve", "migrate", "check-db"):
        sub.add_parser(action).add_argument("service", choices=("web", *DATABASES) if action == "serve" else DATABASES)
    sub.add_parser("create-first-admin").add_argument("--email", required=True)
    sub.add_parser("bootstrap-jwt").add_argument("directory", type=Path)
    sub.add_parser("consume-codes")
    args = parser.parse_args()
    try:
        if args.action == "serve":
            serve(args.service)
        elif args.action == "migrate":
            migrate(args.service)
            print(f"Migrations applied to {args.service}")
        elif args.action == "check-db":
            print(json.dumps(database_state(database_engine(args.service))))
        elif args.action == "bootstrap-jwt":
            from .security import bootstrap_keys

            bootstrap_keys(args.directory)
        elif args.action == "consume-codes":
            from .noti import consume_codes

            logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
            asyncio.run(consume_codes())
        else:
            print(json.dumps(create_first_admin(args.email)))
    except (EmailNotValidError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
