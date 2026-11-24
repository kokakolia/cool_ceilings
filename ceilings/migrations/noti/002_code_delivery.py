import sqlalchemy as sa
from alembic import op

revision = "noti_002"
down_revision = "noti_001"


def upgrade():
    timestamp = sa.DateTime(timezone=True)
    op.create_table(
        "code_deliveries",
        sa.Column("command_id", sa.Uuid(), primary_key=True),
        sa.Column("expires_at", timestamp, nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("retry_at", timestamp),
        sa.CheckConstraint("state IN ('sending', 'retry', 'sent', 'failed', 'unknown', 'expired')"),
        schema="app",
    )
    op.create_index("code_deliveries_expiry", "code_deliveries", ["expires_at"], schema="app")


def downgrade():
    op.drop_table("code_deliveries", schema="app")
