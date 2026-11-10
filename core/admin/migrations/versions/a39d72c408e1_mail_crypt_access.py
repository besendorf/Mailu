"""Credential-encrypted webmail sessions and OAuth grants.

Revision ID: a39d72c408e1
Revises: 7e83a9c0d142
"""
from alembic import op
import sqlalchemy as sa

revision = 'a39d72c408e1'
down_revision = '7e83a9c0d142'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('mail_crypt_session',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('user_email', sa.String(255), sa.ForeignKey('user.email'), nullable=False),
        sa.Column('session_hash', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.Integer(), nullable=False),
        sa.Column('envelope', sa.Text(), nullable=False))
    op.create_index('ix_mail_crypt_session_expires_at', 'mail_crypt_session', ['expires_at'])
    op.add_column('oauth2_authorization_code', sa.Column('mail_crypt_envelope', sa.Text(), nullable=True))
    op.add_column('oauth2_grant', sa.Column('mail_crypt_envelope', sa.Text(), nullable=True))


def downgrade():
    # Password, app-token and recovery envelopes remain intact in mail_crypt_key.
    op.drop_column('oauth2_grant', 'mail_crypt_envelope')
    op.drop_column('oauth2_authorization_code', 'mail_crypt_envelope')
    op.drop_index('ix_mail_crypt_session_expires_at', table_name='mail_crypt_session')
    op.drop_table('mail_crypt_session')
