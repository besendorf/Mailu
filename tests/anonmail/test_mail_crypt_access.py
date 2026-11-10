"""Encrypted mailbox access across browser, OAuth, and recovery lifecycles."""
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from mailu import mail_crypt, mail_crypt_envelope as envelope, models, oauth2
from .test_mail_crypt import encrypted_user, private
from .test_oauth_server import pkce_pair, sign_in_test_user


def authorize(client, user):
    sign_in_test_user(client, user)
    verifier, challenge = pkce_pair()
    request = dict(client_id='mailu', response_type='code', redirect_uri='http://127.0.0.1:49152/',
                   scope='imap smtp offline_access', code_challenge=challenge, code_challenge_method='S256')
    assert client.get('/admin/oauth2/authorize', query_string=request).status_code == 200
    data = dict(request, selected_scopes=['imap', 'smtp', 'offline_access'], approve='Allow access')
    assert client.post('/admin/oauth2/authorize', data=data).status_code == 400
    data['mailbox_password'] = 'test-password'
    result = client.post('/admin/oauth2/authorize', data=data)
    assert result.status_code == 302
    code = parse_qs(urlsplit(result.location).query)['code'][0]
    record = models.OAuth2AuthorizationCode.query.one()
    assert code not in record.mail_crypt_envelope and 'PRIVATE KEY' not in record.mail_crypt_envelope
    result = client.post('/admin/oauth2/token', data=dict(grant_type='authorization_code', client_id='mailu',
        code=code, redirect_uri=request['redirect_uri'], code_verifier=verifier))
    assert result.status_code == 200
    return result.json


def test_oauth_unlock_refresh_replay_and_no_server_reconstruction(app, client, encrypted_user):
    app.config['WTF_CSRF_ENABLED'] = False
    tokens = authorize(client, encrypted_user)
    grant = models.OAuth2Grant.query.one()
    assert tokens['access_token'].startswith('v2.')
    seed = tokens['access_token'].split('.')[4]
    assert seed not in grant.mail_crypt_envelope
    assert tokens['refresh_token'].split('.')[4] == seed
    response = client.post('/internal/oauth2/introspect', data={'token': tokens['access_token']},
                           headers={'X-Dovecot-Auth-Protocol': 'imap'})
    assert response.json['active'] is True
    assert response.headers['Cache-Control'] == 'no-store'
    prefetched = dict(field.split('=', 1) for field in response.json['mail_crypt_userdb'].split('\t'))
    assert prefetched['crypt_global_private_key/mailu/crypt_private_key_file'] == private(encrypted_user)['crypt_global_private_key/mailu/crypt_private_key_file']
    forged = oauth2._derive_mail_token('access', grant.grant_id, 0)
    assert client.post('/internal/oauth2/introspect', data={'token': forged}).json == {'active': False}
    wrong_seed = oauth2._derive_mail_token('access', grant.grant_id, 0, 'z' * 43)
    assert client.post('/internal/oauth2/introspect', data={'token': wrong_seed}).json == {'active': False}
    refreshed = client.post('/admin/oauth2/token', data=dict(grant_type='refresh_token', client_id='mailu', refresh_token=tokens['refresh_token']))
    assert refreshed.status_code == 200
    assert client.post('/internal/oauth2/introspect', data={'token': tokens['access_token']}).json == {'active': False}
    assert client.post('/internal/oauth2/introspect', data={'token': refreshed.json['access_token']}).json['active']
    assert client.post('/admin/oauth2/token', data=dict(grant_type='refresh_token', client_id='mailu', refresh_token=tokens['refresh_token'])).status_code == 400
    assert client.post('/internal/oauth2/introspect', data={'token': refreshed.json['access_token']}).json == {'active': False}


def test_webmail_unlock_cookie_is_session_bound_expires_and_revokes(app, client, encrypted_user):
    app.config['WTF_CSRF_ENABLED'] = False
    sign_in_test_user(client, encrypted_user)  # Same session state as passkey login, without a password.
    assert client.get('/internal/auth/user').status_code == 403
    response = client.post('/admin/user/encryption', data={'password': 'wrong', 'unlock': '1'})
    assert response.status_code == 400
    response = client.post('/admin/user/encryption', data={'password': 'test-password', 'unlock': '1'})
    assert response.status_code == 302 and response.location == app.config['WEB_WEBMAIL']
    assert 'HttpOnly' in response.headers['Set-Cookie'] and 'SameSite=Strict' in response.headers['Set-Cookie']
    auth = client.get('/internal/auth/user')
    assert auth.status_code == 200
    secret = auth.headers['X-User-Token']
    record = models.MailCryptSession.query.one()
    assert secret not in record.envelope and secret != record.token_hash
    assert private(encrypted_user, secret, port='10143') == private(encrypted_user)
    with pytest.raises(mail_crypt.MailCryptError):
        private(encrypted_user, secret, port='993')
    second = app.test_client()
    sign_in_test_user(second, encrypted_user)
    second.set_cookie(mail_crypt.WEBMAIL_COOKIE, secret)
    assert second.get('/internal/auth/user').status_code == 403
    record.expires_at = int(time.time()) - 1
    models.db.session.commit()
    assert client.get('/internal/auth/user').status_code == 403
    with pytest.raises(mail_crypt.MailCryptError):
        private(encrypted_user, secret, port='10143')
    client.post('/admin/user/encryption', data={'password': 'test-password', 'unlock': '1'})
    assert client.get('/internal/auth/user').status_code == 200
    client.get('/sso/logout')
    assert models.MailCryptSession.query.count() == 0


def test_recovery_token_rotation_and_password_recovery_preserve_key(app, client, encrypted_user):
    app.config['WTF_CSRF_ENABLED'] = False
    old_pem = private(encrypted_user)
    token = mail_crypt.recovery_token(encrypted_user, 'test-password')
    models.db.session.commit()
    newer = mail_crypt.recovery_token(encrypted_user, 'test-password')
    models.db.session.commit()
    with pytest.raises(envelope.KeyringError):
        envelope.unlock(mail_crypt.document(encrypted_user), 'recovery', token, mailbox_id=encrypted_user.mail_crypt_key.mailbox_id)
    sign_in_test_user(client, encrypted_user)
    result = client.post('/admin/user/encryption', data={'password': newer, 'new_password': 'replacement-password',
                                                       'confirm_password': 'replacement-password', 'recover': '1'})
    assert result.status_code == 302
    assert encrypted_user.check_password('replacement-password')
    assert 'recovery' not in mail_crypt.document(encrypted_user)['slots']
    assert private(encrypted_user, 'replacement-password') == old_pem
    assert models.MailCryptSession.query.count() == 0


def test_oauth_prefetch_rejects_stored_control_characters(app, client, encrypted_user, monkeypatch):
    app.config['WTF_CSRF_ENABLED'] = False
    tokens = authorize(client, encrypted_user)
    from mailu.internal.views import dovecot
    original = dovecot._userdb_fields

    def injected(user):
        return {**original(user), 'home': '/mail/alice\tuid=0'}

    monkeypatch.setattr(dovecot, '_userdb_fields', injected)
    assert client.post('/internal/oauth2/introspect', data={'token': tokens['access_token']}).json == {'active': False}


def test_expired_unlock_routes_to_unlock_without_capturing_admin_at_root(app, client, encrypted_user):
    app.config.update(WEB_WEBMAIL='/', WEBMAIL='roundcube')
    sign_in_test_user(client, encrypted_user)
    assert client.get('/sso/login/admin').location == '/admin'
    assert client.get('/sso/login/webmail').location == '/admin/user/encryption'
