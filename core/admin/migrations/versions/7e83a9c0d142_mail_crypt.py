"""Store per-mailbox encrypted key envelopes.

Revision ID: 7e83a9c0d142
Revises: b5e8d1a4c2f0
"""
from alembic import op
import sqlalchemy as sa

revision = '7e83a9c0d142'
down_revision = 'b5e8d1a4c2f0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'mail_crypt_key',
        sa.Column('user_email', sa.String(255), sa.ForeignKey('user.email'), primary_key=True),
        sa.Column('mailbox_id', sa.String(36), nullable=False, unique=True),
        sa.Column('envelope', sa.Text(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
    )


def downgrade():
    # Dropping this table can irreversibly destroy access to encrypted mail.
    bind = op.get_bind()
    if bind.execute(sa.text('SELECT COUNT(*) FROM mail_crypt_key')).scalar():
        raise RuntimeError('Decrypt all mailboxes and export their key envelopes before downgrading; encryption key records still exist.')
    op.drop_table('mail_crypt_key')
