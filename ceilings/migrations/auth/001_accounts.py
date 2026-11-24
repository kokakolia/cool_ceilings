import sqlalchemy as sa
from alembic import op


revision = "auth_001"
down_revision = None


def upgrade():
    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('client', 'admin')", name="account_role"),
        sa.UniqueConstraint("email", "role", name="account_email_role"),
        schema="app",
    )


def downgrade():
    op.drop_table("accounts", schema="app")
