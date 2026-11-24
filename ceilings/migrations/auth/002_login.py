import sqlalchemy as sa
from alembic import op

revision = "auth_002"
down_revision = "auth_001"


def upgrade():
    timestamp = sa.DateTime(timezone=True)
    op.create_table(
        "login_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("purpose", sa.String(10), nullable=False),
        sa.Column("digest", sa.LargeBinary(), nullable=False),
        sa.Column("issued_at", timestamp, nullable=False),
        sa.Column("expires_at", timestamp, nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consumed_at", timestamp),
        sa.Column("cancelled_at", timestamp),
        schema="app",
    )
    op.create_index("login_codes_email_purpose_issued", "login_codes", ["email", "purpose", "issued_at"], schema="app")
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("app.accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(10), nullable=False),
        sa.Column("expires_at", timestamp, nullable=False),
        sa.Column("revoked_at", timestamp),
        schema="app",
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("digest", sa.LargeBinary(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("app.sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("used_at", timestamp),
        schema="app",
    )
    op.create_index("refresh_tokens_session", "refresh_tokens", ["session_id"], schema="app")


def downgrade():
    for table in ("refresh_tokens", "sessions", "login_codes"):
        op.drop_table(table, schema="app")
