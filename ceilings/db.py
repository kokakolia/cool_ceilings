from pathlib import Path

from sqlalchemy import URL, create_engine, text
from sqlalchemy.pool import NullPool


DATABASES = ("auth", "order", "noti")


def database_engine(service, migrate=False):
    if service not in DATABASES:
        raise ValueError(f"No database for {service}")
    role = "migrator" if migrate else "app_user"
    password = Path(f"/run/secrets/db_{role}").read_text().strip()
    url = URL.create(
        "postgresql+psycopg",
        username=role,
        password=password,
        host=f"pg-{service}.ceilings.test",
        database=f"ceilings_{service}",
        query={"sslmode": "verify-full", "sslrootcert": "/run/trust/root.crt", "connect_timeout": "3"},
    )
    return create_engine(url, poolclass=NullPool)


def database_state(engine):
    with engine.connect() as connection:
        database, role, encrypted = connection.execute(text(
            "SELECT current_database(), current_user, ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        )).one()
        revision = connection.scalar(text("SELECT version_num FROM app.alembic_version"))
    return {"database": database, "role": role, "tls": encrypted, "revision": revision}
