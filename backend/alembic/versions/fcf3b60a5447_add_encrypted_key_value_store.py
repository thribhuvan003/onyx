"""add encrypted key value store

Revision ID: fcf3b60a5447
Revises: 7f2a3b9c1d4e
Create Date: 2026-07-02 15:09:28.868857

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert


# revision identifiers, used by Alembic.
revision = "fcf3b60a5447"
down_revision = "7f2a3b9c1d4e"
branch_labels = None
depends_on = None


key_value_store = sa.table(
    "key_value_store",
    sa.column("key", sa.String),
    sa.column("encrypted_value", sa.LargeBinary),
)

encrypted_key_value_store = sa.table(
    "encrypted_key_value_store",
    sa.column("key", sa.String),
    sa.column("value", sa.LargeBinary),
)

# Instance-default Google OAuth app credentials previously kept in the KV store.
APP_CRED_KEYS = ["google_drive_app_credential", "gmail_app_credential"]


def upgrade() -> None:
    op.create_table(
        "encrypted_key_value_store",
        sa.Column("key", sa.String(), primary_key=True),
        sa.Column("value", sa.LargeBinary(), nullable=False),
    )

    # Seed the default from the old KV keys. Both columns are Fernet-encrypted
    # LargeBinary under the same key, so the ciphertext copies directly.
    app_creds = sa.select(
        key_value_store.c.key, key_value_store.c.encrypted_value
    ).where(
        key_value_store.c.key.in_(APP_CRED_KEYS),
        key_value_store.c.encrypted_value.is_not(None),
    )
    op.execute(
        pg_insert(encrypted_key_value_store)
        .from_select(["key", "value"], app_creds)
        .on_conflict_do_nothing(index_elements=["key"])
    )


def downgrade() -> None:
    op.drop_table("encrypted_key_value_store")
