"""copy telemetry secrets to encrypted kv

Revision ID: f6b0949ea33d
Revises: fcf3b60a5447
Create Date: 2026-07-02 18:36:07.598687

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert


# revision identifiers, used by Alembic.
revision = "f6b0949ea33d"
down_revision = "fcf3b60a5447"
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

# Instance telemetry secrets previously kept in the KV store.
TELEMETRY_KEYS = ["customer_uuid", "instance_domain"]


def upgrade() -> None:
    # Both columns are Fernet-encrypted LargeBinary under the same key, so the
    # ciphertext copies directly.
    telemetry_secrets = sa.select(
        key_value_store.c.key, key_value_store.c.encrypted_value
    ).where(
        key_value_store.c.key.in_(TELEMETRY_KEYS),
        key_value_store.c.encrypted_value.is_not(None),
    )
    op.execute(
        pg_insert(encrypted_key_value_store)
        .from_select(["key", "value"], telemetry_secrets)
        .on_conflict_do_nothing(index_elements=["key"])
    )


def downgrade() -> None:
    # Reverse of upgrade: drop the copies. The KV source rows are untouched, so
    # old code keeps reading the telemetry secrets from the KV store.
    op.execute(
        encrypted_key_value_store.delete().where(
            encrypted_key_value_store.c.key.in_(TELEMETRY_KEYS)
        )
    )
