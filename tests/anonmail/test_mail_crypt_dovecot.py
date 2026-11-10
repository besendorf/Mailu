"""Real Dovecot 2.4 storage tests, runnable without root or a master daemon.

Set DOVECOT_TEST_IMAP, DOVECOT_TEST_DOVEADM, DOVECOT_TEST_LIBEXEC,
DOVECOT_TEST_MODULES and optional DOVECOT_TEST_PREFIX (JSON argv prefix).
All keys here are disposable test keys. Runtime -o overrides exercise the same
settings override parser used by prefetched userdb fields.
"""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import imaplib
import smtplib
import socket
import subprocess
import threading
import time
import tempfile

import pytest

from mailu import mail_crypt
from .test_mail_crypt import encrypted_user, private


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('encrypt_maildir', ROOT / 'core/dovecot/encrypt_maildir.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

pytestmark = pytest.mark.skipif(not os.environ.get('DOVECOT_TEST_IMAP'), reason='Set DOVECOT_TEST_IMAP to run real Dovecot storage tests')
MESSAGE = b'Subject: private subject 948277\r\n\r\nprivate-body-948277\r\n'


@pytest.fixture
def dovecot(tmp_path):
    prefix = json.loads(os.environ.get('DOVECOT_TEST_PREFIX', '[]'))
    home = tmp_path / 'home'
    home.mkdir()
    configuration = tmp_path / 'dovecot.conf'
    configuration.write_text(f'''
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0
base_dir = {tmp_path}/run
state_dir = {tmp_path}/state
libexec_dir = {os.environ['DOVECOT_TEST_LIBEXEC']}
mail_plugin_dir = {os.environ['DOVECOT_TEST_MODULES']}
log_path = /dev/stderr
mail_driver = maildir
mail_path = ~/mail
mail_home = {home}
mail_uid = {os.getuid()}
mail_gid = {os.getgid()}
first_valid_uid = {os.getuid()}
mail_plugins {{
 mail_crypt = yes
}}
crypt_write_algorithm =
stats_writer_socket_path =
import_environment {{
 LD_LIBRARY_PATH = %{{env:LD_LIBRARY_PATH}}
 USER = {pwd.getpwuid(os.getuid()).pw_name}
 HOME = {home}
}}
''')

    def run(data, fields, target_home=None, compression=False):
        command = prefix + [os.environ['DOVECOT_TEST_IMAP'], '-c', str(configuration)]
        if target_home:
            command += ['-o', f'mail_home={target_home}']
        if compression:
            command += ['-o', 'mail_plugins/mail_compress=yes', '-o', 'mail_compress_write_method=gz']
        for key, value in fields.items():
            command += ['-o', f'{key}={value}']
        command += ['-o', f'mail_temp_dir={tmp_path}']
        return subprocess.run(command, input=data, capture_output=True, timeout=20)
    return run, home, configuration, prefix


def append(run, fields, **kw):
    data = b'a1 APPEND INBOX {' + str(len(MESSAGE)).encode() + b'+}\r\n' + MESSAGE + b'\r\na2 LOGOUT\r\n'
    result = run(data, fields, **kw)
    assert b'a1 OK' in result.stdout, result.stderr.decode()


def fetch(run, fields, **kw):
    return run(b'a1 SELECT INBOX\r\na2 FETCH 1 BODY[]\r\na3 LOGOUT\r\n', fields, **kw)


@pytest.mark.parametrize('compression', [False, True])
def test_public_key_only_write_and_private_key_read(dovecot, encrypted_user, compression):
    run, home, _config, _prefix = dovecot
    public = mail_crypt.public_fields(encrypted_user)
    append(run, public, compression=compression)
    messages = list((home / 'mail/new').iterdir())
    assert len(messages) == 1
    assert messages[0].read_bytes().startswith(migration.MAGIC)
    for path in home.rglob('*'):
        if path.is_file():
            assert b'private-body-948277' not in path.read_bytes()
            assert b'private subject 948277' not in path.read_bytes()
    locked = fetch(run, public, compression=compression)
    assert b'private-body-948277' not in locked.stdout
    unlocked = fetch(run, {**public, **private(encrypted_user)}, compression=compression)
    assert MESSAGE in unlocked.stdout, unlocked.stderr.decode()
    for path in home.rglob('*'):
        if path.is_file():
            assert b'private-body-948277' not in path.read_bytes()
            assert b'private subject 948277' not in path.read_bytes()


def test_missing_public_key_refuses_write_instead_of_plaintext_fallback(dovecot):
    run, home, _config, _prefix = dovecot
    data = b'a1 APPEND INBOX {' + str(len(MESSAGE)).encode() + b'+}\r\n' + MESSAGE + b'\r\na2 LOGOUT\r\n'
    result = run(data, {'crypt_write_algorithm': 'aes-256-gcm-sha256'})
    assert b'a1 OK' not in result.stdout
    assert not list(home.rglob('new/*'))


def test_public_key_only_sieve_delivery(dovecot, encrypted_user, tmp_path):
    run, home, config, prefix = dovecot
    lda = os.environ.get('DOVECOT_TEST_LDA')
    if not lda:
        pytest.skip('Set DOVECOT_TEST_LDA for delivery with Sieve')
    script = tmp_path / 'delivery.sieve'
    script.write_text('require ["fileinto", "mailbox"]; fileinto :create "Archive";\n')
    with config.open('a') as handle:
        handle.write(f'''\nmail_plugins {{
 sieve = yes
 quota = yes
}}
quota User {{
 driver = count
}}
sieve_script test {{
 type = before
 driver = file
 path = {script}
}}
''')
    command = prefix + [lda, '-c', str(config)]
    for key, value in mail_crypt.public_fields(encrypted_user).items():
        command += ['-o', f'{key}={value}']
    command += ['-o', f'mail_temp_dir={tmp_path}']
    # Separate processes have no retained private key or in-memory index.
    for _ in range(2):
        result = subprocess.run(command, input=MESSAGE, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr.decode()
        assert b'Error:' not in result.stderr, result.stderr.decode()
    files = list((home / 'mail/.Archive/new').glob('*'))
    assert len(files) == 2, result.stderr.decode()
    assert all(file.read_bytes().startswith(migration.MAGIC) for file in files)
    fields = {**mail_crypt.public_fields(encrypted_user), **private(encrypted_user)}
    fields['mail_plugins/sieve'] = 'no'
    result = run(b'a1 SELECT Archive\r\na2 FETCH 1 BODY[]\r\na3 LOGOUT\r\n', fields)
    assert MESSAGE in result.stdout, result.stderr.decode()


def test_large_message_partial_read_uses_configured_temporary_directory(dovecot, encrypted_user):
    run, home, _config, _prefix = dovecot
    public = mail_crypt.public_fields(encrypted_user)
    message = b'Subject: large mail\r\n\r\n' + b'abcdefgh' * 65536 + b'\r\n'
    result = run(b'a1 APPEND INBOX {' + str(len(message)).encode() + b'+}\r\n' + message + b'\r\na2 LOGOUT\r\n', public)
    assert b'a1 OK' in result.stdout, result.stderr.decode()
    fields = {**public, **private(encrypted_user)}
    result = run(b'a1 SELECT INBOX\r\na2 FETCH 1 BODY.PEEK[TEXT]<350000.128>\r\na3 LOGOUT\r\n', fields)
    assert b'abcdefgh' * 16 in result.stdout, result.stderr.decode()
    for path in home.rglob('*'):
        if path.is_file():
            assert b'abcdefgh' * 16 not in path.read_bytes()


def test_unencrypted_accounts_are_unchanged(dovecot):
    run, home, _config, _prefix = dovecot
    append(run, {})
    assert b'private-body-948277' in next((home / 'mail/new').iterdir()).read_bytes()
    assert MESSAGE in fetch(run, {}).stdout


def test_global_key_mode_is_scoped_per_user_without_folder_keys(dovecot, encrypted_user):
    from mailu import models
    run, _home, _config, _prefix = dovecot
    other = models.User(localpart='bob', domain=encrypted_user.domain)
    other.set_password('other-password')
    models.db.session.add(other)
    models.db.session.commit()
    mail_crypt.enable(other, 'other-password')
    models.db.session.commit()
    alice_public = mail_crypt.public_fields(encrypted_user)
    bob_public = mail_crypt.public_fields(other)
    assert alice_public['crypt_global_public_key_file'] != bob_public['crypt_global_public_key_file']
    assert not any('crypt_user_key' in key for key in alice_public)
    append(run, alice_public)
    # Give the reader Bob's valid private key while retaining Alice's mailbox.
    # Loading a valid key is insufficient: it must match the message recipient.
    bob_private = private(other, 'other-password')
    wrong_user = fetch(run, {**alice_public, **bob_private})
    assert MESSAGE not in wrong_user.stdout
    assert b'private-body-948277' not in wrong_user.stdout
    assert MESSAGE in fetch(run, {**alice_public, **private(encrypted_user)}).stdout


def test_offline_migration_preserves_uids_flags_and_source(dovecot, encrypted_user, tmp_path):
    run, home, config, prefix = dovecot
    append(run, {})
    initial = fetch(run, {})
    assert MESSAGE in initial.stdout
    uidlist = (home / 'mail/dovecot-uidlist').read_bytes()
    filenames = sorted(path.name for path in (home / 'mail/cur').iterdir())
    source_snapshot = {str(path.relative_to(home)): path.read_bytes() for path in home.rglob('*') if path.is_file()}
    public_file = tmp_path / 'public.pem'
    public_file.write_bytes(mail_crypt.envelope.public_pem(mail_crypt.document(encrypted_user)))
    destination = tmp_path / 'migrated'
    result = migration.migrate(home, destination, public_file, config=str(config),
                               doveadm=prefix + [os.environ['DOVECOT_TEST_DOVEADM']])
    assert result['encrypted_messages'] == 1
    assert (destination / migration.COMPLETE).is_file()
    assert (destination / 'mail/dovecot-uidlist').read_bytes() == uidlist
    assert sorted(path.name for path in (destination / 'mail/cur').iterdir()) == filenames
    assert {str(path.relative_to(home)): path.read_bytes() for path in home.rglob('*') if path.is_file()} == source_snapshot
    assert not list(destination.rglob('dovecot.index*'))
    assert all(path.read_bytes().startswith(migration.MAGIC) for path in (destination / 'mail/cur').iterdir())
    fields = {**mail_crypt.public_fields(encrypted_user), **private(encrypted_user)}
    assert MESSAGE in fetch(run, fields, target_home=destination).stdout


def test_migration_rejects_existing_or_nested_destinations(dovecot, tmp_path):
    _run, home, _config, _prefix = dovecot
    public_file = tmp_path / 'unused-public.pem'
    public_file.write_text('test')
    link = tmp_path / 'link'
    link.symlink_to(home, target_is_directory=True)
    for target in (home, home / 'nested', link / 'nested'):
        with pytest.raises(ValueError):
            migration.migrate(home, target, public_file)


def test_daemon_lmtp_and_authenticated_lua_prefetch(dovecot, encrypted_user, app, monkeypatch, tmp_path):
    """Full daemon test for CI/hosts allowing Unix sockets; no privileged ports."""
    from jinja2 import Template
    from werkzeug.serving import make_server
    from mailu import models
    from mailu.internal.views import dovecot as views

    master = os.environ.get('DOVECOT_TEST_MASTER')
    if not master:
        pytest.skip('Set DOVECOT_TEST_MASTER for full daemon integration')
    try:
        probe = socket.socket(socket.AF_UNIX)
        probe.close()
    except OSError:
        pytest.skip('Execution host prohibits Unix-domain sockets required by the Dovecot daemon')
    if os.getuid() == 0:
        pytest.skip('Run the rootless daemon test as a non-root user')
    _run, home, config, prefix = dovecot
    # The test's trusted proxy/backend peer is loopback, not the deployment's
    # Docker subnet used by allow_real_nets in Mailu's passdb response.
    app.config['SUBNET'] = '127.0.0.0/8'
    encrypted_user.dovecot_uid = os.getuid()
    models.db.session.commit()
    original_fields = views._userdb_fields

    def fields(user):
        result = original_fields(user)
        target = home if user.email == encrypted_user.email else tmp_path / 'plain-home'
        target.mkdir(exist_ok=True)
        result.update(home=str(target), uid=os.getuid(), gid=os.getgid(), mail_temp_dir=str(tmp_path))
        return result

    monkeypatch.setattr(views, '_userdb_fields', fields)
    http = make_server('127.0.0.1', 0, app)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()

    def free_port():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    imap_port, lmtp_port = free_port(), free_port()
    runtime_directory = tempfile.TemporaryDirectory(prefix='mcry-')
    login = Template((ROOT / 'core/dovecot/conf/login.lua').read_text()).render(ADMIN_ADDRESS='127.0.0.1')
    # Debian's JSON decoder has the same interface as Alpine's lua-json4.
    login = login.replace("require('json')", "require('cjson')")
    login = login.replace('127.0.0.1:8080', f'127.0.0.1:{http.server_port}')
    login_path = tmp_path / 'login.lua'
    login_path.write_text(login)
    unix_user = pwd.getpwuid(os.getuid()).pw_name
    unix_group = __import__('grp').getgrgid(os.getgid()).gr_name
    with config.open('a') as handle:
        handle.write(f'''
base_dir = {runtime_directory.name}/run
protocols {{
 imap = yes
 lmtp = yes
}}
listen = 127.0.0.1
ssl = no
auth_allow_cleartext = yes
default_internal_user = {unix_user}
default_internal_group = {unix_group}
default_login_user = {unix_user}
postmaster_address = postmaster@example.org
passdb lua {{
 mechanisms_filter = plain login
 lua_file = {login_path}
 use_worker = yes
}}
userdb prefetch {{
}}
userdb lua {{
 lua_file = {login_path}
 use_worker = yes
}}
service auth {{
 user = {unix_user}
}}
service auth-worker {{
 user = {unix_user}
}}
service imap-login {{
 chroot =
 inet_listener imap {{
  port = {imap_port}
 }}
}}
service lmtp {{
 inet_listener lmtp {{
  port = {lmtp_port}
 }}
}}
''')
    source = (ROOT / 'core/dovecot/conf/dovecot.conf').read_text()
    start = source.index('\noauth2 {')
    stop = source.index('\nservice auth {', start)
    oauth_config = source[start:stop].replace('{{ ADMIN_ADDRESS }}:8080', f'127.0.0.1:{http.server_port}')
    with app.test_request_context('/'):
        from mailu.oauth2 import issuer
        oauth_config = oauth_config.replace('{{ oauth2_issuers }}', issuer())
    with config.open('a') as handle:
        handle.write(oauth_config + '\nauth_mechanisms {\n plain = yes\n xoauth2 = yes\n}\n')
    process = subprocess.Popen(prefix + [master, '-F', '-c', str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with socket.create_connection(('127.0.0.1', lmtp_port), timeout=0.2):
                    break
            except OSError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    process.terminate()
                    _out, error = process.communicate(timeout=5)
                    pytest.fail(error.decode())
                time.sleep(0.05)
        # No IMAP login has occurred: LMTP must deliver using only the public key.
        with smtplib.LMTP('127.0.0.1', lmtp_port, timeout=20) as delivery:
            assert delivery.sendmail('sender@example.org', [encrypted_user.email], MESSAGE) == {}
        files = list((home / 'mail/new').glob('*'))
        assert len(files) == 1 and files[0].read_bytes().startswith(migration.MAGIC)
        with imaplib.IMAP4('127.0.0.1', imap_port, timeout=20) as client:
            with pytest.raises(imaplib.IMAP4.error):
                client.login(encrypted_user.email, 'wrong')
            assert client.login(encrypted_user.email, 'test-password')[0] == 'OK'
            assert client.select('INBOX')[0] == 'OK'
            status, data = client.fetch('1', '(BODY[])')
            assert status == 'OK' and any(MESSAGE in item[1] for item in data if isinstance(item, tuple))
        raw_token = 'c' * 32
        token = models.Token(user=encrypted_user)
        token.set_password(raw_token)
        models.db.session.add(token)
        models.db.session.flush()
        mail_crypt.enroll_token(encrypted_user, token, raw_token, 'test-password')
        models.db.session.commit()
        app.config['AUTH_REQUIRE_TOKENS'] = True
        with imaplib.IMAP4('127.0.0.1', imap_port, timeout=20) as client:
            assert client.login(encrypted_user.email, raw_token)[0] == 'OK'
            assert client.select('INBOX')[0] == 'OK'
            status, data = client.fetch('1', '(BODY[])')
            assert status == 'OK' and any(MESSAGE in item[1] for item in data if isinstance(item, tuple))
        # Full XOAUTH2 handshake must carry the key through the Lua userdb.
        from mailu import oauth2
        with app.test_request_context('/admin/oauth2/token'):
            seed = 'x' * 43
            wrapped = mail_crypt.wrap(encrypted_user, seed, unlock_secret='test-password')
            tokens = oauth2._issue_tokens(encrypted_user.email, 'mailu', 'imap offline_access', unlock_secret=seed, wrapped=wrapped)
        bearer = tokens['access_token']
        with imaplib.IMAP4('127.0.0.1', imap_port, timeout=20) as client:
            assert client.authenticate('XOAUTH2', lambda _: f'user={encrypted_user.email}\x01auth=Bearer {bearer}\x01\x01'.encode())[0] == 'OK'
            assert client.select('INBOX')[0] == 'OK'
            status, data = client.fetch('1', '(BODY[])')
            assert status == 'OK' and any(MESSAGE in item[1] for item in data if isinstance(item, tuple))
        # A webmail credential can also decrypt after front's trusted backend hop.
        secret = mail_crypt.unlock_webmail(encrypted_user, 'test-password', 'test-session')
        from mailu.internal import nginx
        monkeypatch.setattr(nginx, 'WEBMAIL_PORTS', nginx.WEBMAIL_PORTS + [str(imap_port)])
        with imaplib.IMAP4('127.0.0.1', imap_port, timeout=20) as client:
            assert client.login(encrypted_user.email, secret)[0] == 'OK'
            assert client.select('INBOX')[0] == 'OK'
            status, data = client.fetch('1', '(BODY[])')
            assert status == 'OK' and any(MESSAGE in item[1] for item in data if isinstance(item, tuple))
        # OAuth does not add an empty mail-crypt key to unencrypted accounts.
        plain = models.User(localpart='plain', domain=encrypted_user.domain)
        plain.set_password('plain-password')
        models.db.session.add(plain)
        models.db.session.commit()
        with app.test_request_context('/admin/oauth2/token'):
            plain_tokens = oauth2._issue_tokens(plain.email, 'mailu', 'imap')
        with imaplib.IMAP4('127.0.0.1', imap_port, timeout=20) as client:
            plain_bearer = plain_tokens['access_token']
            assert client.authenticate('XOAUTH2', lambda _: f'user={plain.email}\x01auth=Bearer {plain_bearer}\x01\x01'.encode())[0] == 'OK'
            assert client.append('INBOX', None, None, MESSAGE)[0] == 'OK'
            assert client.select('INBOX')[0] == 'OK'
            status, data = client.fetch('1', '(BODY[])')
            assert status == 'OK' and any(MESSAGE in item[1] for item in data if isinstance(item, tuple))
        assert any(b'private-body-948277' in path.read_bytes() for path in (tmp_path / 'plain-home' / 'mail').rglob('*') if path.is_file())
    finally:
        process.terminate()
        _out, diagnostics = process.communicate(timeout=5)
        if diagnostics:
            print(diagnostics.decode(errors='replace'))
        http.shutdown()
        thread.join(timeout=5)
        runtime_directory.cleanup()
