import pytest
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from mailu import mail_crypt, mail_crypt_envelope as envelope, models, setup_tokens


@pytest.fixture
def encrypted_user(app):
    with app.app_context():
        app.config['AUTH_REQUIRE_TOKENS'] = False
        models.User._ctx = None
        domain = models.Domain(name='example.org')
        user = models.User(localpart='alice', domain=domain)
        user.set_password('test-password')
        models.db.session.add(user)
        models.db.session.commit()
        mail_crypt.enable(user, 'test-password')
        models.db.session.commit()
        yield user


def private(user, password='test-password', **kw):
    return mail_crypt.private_fields(user, password, kw.get('ip', '192.0.2.1'),
                                    kw.get('protocol', 'imap'), kw.get('port', '993'))


def test_enrollment_stores_only_wrapped_keys(encrypted_user):
    user = encrypted_user
    assert 'PRIVATE KEY' not in user.mail_crypt_key.envelope
    assert 'test-password' not in user.mail_crypt_key.envelope
    assert private(user)['crypt_global_private_key'] == 'mailu'
    with pytest.raises(mail_crypt.MailCryptError):
        mail_crypt.enable(user, 'test-password')


def test_userdb_and_iteration_never_release_private_key(client, encrypted_user):
    for path in ('/internal/dovecot/userdb/alice@example.org', '/internal/dovecot/userdb/?with_uid=1'):
        response = client.get(path)
        assert response.status_code == 200
        result = response.json[0] if isinstance(response.json, list) else response.json
        assert result['crypt_write_algorithm'] == 'aes-256-gcm-sha256'
        assert result['crypt_global_private_key'] == ''
        assert 'crypt_global_private_key/mailu/crypt_private_key_file' not in result
        assert result['mail_plugins/fts'] == 'no'
        assert result['mail_index_path'] == 'MEMORY'
        assert result['mail_temp_dir'] == '/usr/run/mailu-crypt-tmp'


def test_passdb_prefetch_requires_valid_credential(client, encrypted_user):
    path = '/internal/dovecot/passdb/alice@example.org'
    headers = {'Auth-Protocol': 'imap', 'Auth-Port': '993', 'Client-Ip': '192.0.2.1'}
    assert client.get(path, headers=headers).status_code == 403
    headers['Auth-Pass'] = 'wrong'
    assert client.get(path, headers=headers).status_code == 403
    headers['Auth-Pass'] = 'test-password'
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.json['userdb_uid'] == encrypted_user.dovecot_uid
    assert response.json['userdb_crypt_global_private_key'] == 'mailu'
    assert response.json['userdb_crypt_global_private_key/mailu/crypt_private_key_file'].startswith('inline:')


@pytest.mark.parametrize('kw', [{'ip': ''}, {'protocol': 'lmtp'}, {'password': 'wrong'}, {'port': '993', 'ip': 'malformed'}])
def test_unlock_rejects_unsupported_requests(encrypted_user, kw):
    with pytest.raises(mail_crypt.MailCryptError):
        private(encrypted_user, **kw)


def test_disabled_accounts_and_protocol_policy_are_enforced(encrypted_user):
    user = encrypted_user
    user.enabled = False
    with pytest.raises(mail_crypt.MailCryptError):
        private(user)
    user.enabled = True
    user.enable_imap = False
    with pytest.raises(mail_crypt.MailCryptError):
        private(user)


def test_auth_require_tokens_is_preserved(app, encrypted_user):
    app.config['AUTH_REQUIRE_TOKENS'] = True
    with pytest.raises(mail_crypt.MailCryptError):
        private(encrypted_user)


def test_password_change_rewraps_without_rotating_mailbox_key(encrypted_user):
    user = encrypted_user
    original_public = mail_crypt.document(user)['public_key']
    user.set_password('changed-password', unlock_secret='test-password')
    models.db.session.commit()
    assert user.check_password('changed-password')
    assert mail_crypt.document(user)['public_key'] == original_public
    private(user, 'changed-password')
    with pytest.raises(mail_crypt.MailCryptError):
        private(user)


def test_password_reset_and_raw_hash_import_preserve_old_keys(encrypted_user):
    user = encrypted_user
    original_password, original_envelope = user.password, user.mail_crypt_key.envelope
    for kwargs in ({}, {'raw': True}, {'unlock_secret': 'wrong'}):
        with pytest.raises(mail_crypt.MailCryptError):
            user.set_password('replacement', **kwargs)
        assert user.password == original_password
        assert user.mail_crypt_key.envelope == original_envelope
    with pytest.raises(mail_crypt.MailCryptError):
        setup_tokens.issue(user, 3600)
    private(user)


def test_direct_hash_assignment_cannot_bypass_reset_guard(encrypted_user):
    old_password = encrypted_user.password
    with pytest.raises(mail_crypt.MailCryptError):
        encrypted_user.password = 'imported-hash'
    assert encrypted_user.password == old_password


def test_password_and_envelope_rollback_together(encrypted_user):
    user = encrypted_user
    original = user.mail_crypt_key.envelope
    user.set_password('replacement', unlock_secret='test-password')
    models.db.session.flush()
    models.db.session.rollback()
    assert user.mail_crypt_key.envelope == original
    assert user.check_password('test-password')
    assert not user.check_password('replacement')
    private(user)


def test_app_token_requires_explicit_enrollment_and_ip_restrictions(encrypted_user):
    user = encrypted_user
    raw_token = 'a' * 32
    token = models.Token(user=user, ip=['192.0.2.0/24'])
    token.set_password(raw_token)
    models.db.session.add(token)
    models.db.session.commit()
    with pytest.raises(mail_crypt.MailCryptError):
        private(user, raw_token)
    mail_crypt.enroll_token(user, token, raw_token, 'test-password')
    models.db.session.commit()
    assert private(user, raw_token) == private(user)
    with pytest.raises(mail_crypt.MailCryptError):
        private(user, raw_token, ip='198.51.100.1')
    mail_crypt.forget_token(token)
    models.db.session.delete(token)
    models.db.session.commit()
    with pytest.raises(mail_crypt.MailCryptError):
        private(user, raw_token)


def test_enrolled_token_recovers_primary_password_without_old_password(encrypted_user):
    user = encrypted_user
    token = models.Token(user=user)
    token.set_password('b' * 32)
    models.db.session.add(token)
    models.db.session.flush()
    mail_crypt.enroll_token(user, token, 'b' * 32, 'test-password')
    models.db.session.commit()
    public = mail_crypt.document(user)['public_key']
    user.set_password('recovered', unlock_secret='b' * 32, unlock_id=f'token-{token.id}')
    models.db.session.commit()
    assert mail_crypt.document(user)['public_key'] == public
    private(user, 'recovered')


def test_verifier_upgrade_cannot_overwrite_another_enrollment(encrypted_user, monkeypatch):
    user = encrypted_user
    first, second = models.Token(user=user), models.Token(user=user)
    first.set_password('d' * 32)
    second.set_password('e' * 32)
    models.db.session.add_all([first, second])
    models.db.session.commit()
    first_id, second_id = first.id, second.id
    check = first.check_password

    def verify_and_commit(secret):
        valid = check(secret)
        # Model the commit/expiration caused by a legacy verifier upgrade,
        # with another enrollment already committed before it returns.
        result = envelope.add_credential(
            mail_crypt.document(user), f'token-{second_id}', 'e' * 32,
            unlock_id='password', unlock_secret='test-password', mailbox_id=user.mail_crypt_key.mailbox_id,
        )
        user.mail_crypt_key.envelope = envelope.dumps(result)
        models.db.session.commit()
        return valid

    with monkeypatch.context() as patch:
        patch.setattr(first, 'check_password', verify_and_commit)
        mail_crypt.enroll_token(user, first, 'd' * 32, 'test-password')
        models.db.session.commit()
    assert {f'token-{first_id}', f'token-{second_id}'}.issubset(mail_crypt.document(user)['slots'])
    private(user, 'd' * 32)
    private(user, 'e' * 32)


def test_malformed_metadata_fails_closed(client, encrypted_user):
    encrypted_user.mail_crypt_key.envelope = '{}'
    models.db.session.commit()
    response = client.get('/internal/dovecot/userdb/alice@example.org')
    assert response.status_code == 400
    assert 'crypt_write_algorithm' not in response.text


def test_concurrent_enrollment_uses_optimistic_locking(encrypted_user):
    with Session(models.db.engine) as other:
        old = other.get(models.MailCryptKey, encrypted_user.email)
        mail_crypt.rewrap_password(encrypted_user, 'replacement', 'test-password')
        models.db.session.commit()
        old.envelope = old.envelope + ' '
        with pytest.raises(StaleDataError):
            other.commit()


def test_kdf_concurrency_is_bounded(encrypted_user, monkeypatch):
    import threading
    semaphore = threading.BoundedSemaphore(1)
    semaphore.acquire()
    monkeypatch.setattr(mail_crypt, '_unlock_budget', semaphore)
    with pytest.raises(mail_crypt.MailCryptError, match='busy'):
        private(encrypted_user)


def test_oauth_is_rejected_without_unlock(client, encrypted_user, monkeypatch):
    import time
    from mailu.internal.views import oauth2
    grant = models.OAuth2Grant(
        user=encrypted_user, grant_id='test-grant', token_generation=1,
        client_id='test-client', scope='imap', access_expires_at=int(time.time()) + 3600,
    )
    models.db.session.add(grant)
    models.db.session.commit()
    monkeypatch.setattr(oauth2, '_parse_mail_token', lambda *args: ('access', 'test-grant', 1))
    response = client.post('/internal/oauth2/introspect', data={'token': 'valid-access-token'},
                           headers={'X-Dovecot-Auth-Protocol': 'imap'})
    assert response.json == {'active': False}


def test_api_password_reset_failure_is_clean_and_atomic(client, encrypted_user):
    before = encrypted_user.mail_crypt_key.envelope
    headers = {'Authorization': 'Bearer not-empty'}
    response = client.patch('/api/v1/user/alice@example.org', json={'raw_password': 'new'}, headers=headers)
    assert response.status_code == 400
    assert encrypted_user.mail_crypt_key.envelope == before
    assert encrypted_user.check_password('test-password')
    response = client.patch('/api/v1/user/alice@example.org',
                            json={'raw_password': 'new', 'mailbox_unlock_password': 'test-password'}, headers=headers)
    assert response.status_code == 200, response.text
    private(encrypted_user, 'new')


def test_api_token_creation_requires_unlock_and_returns_no_envelopes(client, encrypted_user):
    headers = {'Authorization': 'Bearer not-empty'}
    path = '/api/v1/token'
    response = client.post(path, json={'email': encrypted_user.email}, headers=headers)
    assert response.status_code == 400
    assert not encrypted_user.tokens
    response = client.post(path, json={'email': encrypted_user.email, 'mailbox_password': 'test-password'}, headers=headers)
    assert response.status_code == 200, response.text
    assert 'envelope' not in response.text
    assert 'test-password' not in response.text
    private(encrypted_user, response.json['token'])


def test_cli_key_export_and_recovery_do_not_print_unlock_secret(app, encrypted_user):
    runner = app.test_cli_runner()
    exported = runner.invoke(app.cli, ['mailu', 'mail-crypt', 'export', encrypted_user.email])
    assert exported.exit_code == 0, exported.output
    assert exported.output == encrypted_user.mail_crypt_key.envelope
    changed = runner.invoke(app.cli, ['mailu', 'mail-crypt', 'change-password', encrypted_user.email],
                             input='test-password\nchanged-test\nchanged-test\n')
    assert changed.exit_code == 0, changed.output
    assert 'test-password' not in changed.output
    assert 'changed-test' not in changed.output
    private(encrypted_user, 'changed-test')


def test_cli_restores_original_envelope_and_checks_mailbox_identity(app, encrypted_user, tmp_path):
    user = encrypted_user
    backup = tmp_path / 'envelope.json'
    backup.write_text(user.mail_crypt_key.envelope)
    original = user.mail_crypt_key.envelope
    mailbox_id = user.mail_crypt_key.mailbox_id
    user.mail_crypt_key.envelope = '{}'
    models.db.session.commit()
    runner = app.test_cli_runner()
    args = ['mailu', 'mail-crypt', 'restore', user.email, str(backup), '--mailbox-id', mailbox_id]
    result = runner.invoke(app.cli, args, input='test-password\n')
    assert result.exit_code == 0, result.output
    assert user.mail_crypt_key.envelope == original
    private(user)
    args[-1] = '78658d81-a3cb-421a-9e90-9f328aa2bc89'
    result = runner.invoke(app.cli, args, input='test-password\n')
    assert result.exit_code != 0
    assert user.mail_crypt_key.envelope == original


def test_encryption_status_page_and_webmail_restriction(app, client, encrypted_user):
    app.config['WTF_CSRF_ENABLED'] = False
    with client.session_transaction() as session:
        session['_user_id'] = encrypted_user.email
        session['_fresh'] = True
    response = client.get('/admin/user/encryption')
    assert response.status_code == 200
    assert b'Active sessions keep their previous storage settings' in response.data
    assert b'Create an enrolled app token' in response.data
    assert client.get('/internal/auth/user').status_code == 403


def test_migration_refuses_to_destroy_existing_key_records():
    import importlib.util
    from pathlib import Path
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    path = Path(__file__).resolve().parents[2] / 'core/admin/migrations/versions/7e83a9c0d142_mail_crypt.py'
    spec = importlib.util.spec_from_file_location('crypt_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine('sqlite:///:memory:')
    with engine.begin() as connection:
        connection.execute(sa.text('CREATE TABLE user (email VARCHAR(255) PRIMARY KEY)'))
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        migration.downgrade()
        migration.upgrade()
        connection.execute(sa.text("INSERT INTO user VALUES ('alice@example.org')"))
        connection.execute(sa.text("INSERT INTO mail_crypt_key VALUES ('alice@example.org', 'test-uuid', '{}', 1)"))
        with pytest.raises(RuntimeError, match='encryption key records still exist'):
            migration.downgrade()
        assert connection.execute(sa.text('SELECT COUNT(*) FROM mail_crypt_key')).scalar() == 1


def test_non_encrypted_accounts_keep_their_userdb_fields(app, client):
    with app.app_context():
        domain = models.Domain(name='plain.example')
        user = models.User(localpart='plain', domain=domain)
        user.set_password('test')
        models.db.session.add(user)
        models.db.session.commit()
        assert mail_crypt.public_fields(user) == {}
        assert client.get('/internal/dovecot/passdb/plain@plain.example').status_code == 200
