"""Per-mailbox mail-crypt provisioning and authenticated key release.

Only credential-encrypted private keys are persisted. No unlock cache, recovery
master key, or token-derived server-side fallback is used.
"""

import base64
import copy
import functools
import ipaddress
import hashlib
import secrets
import time

import flask
import threading
import uuid

from flask import current_app as app

from mailu import mail_crypt_envelope as envelope, models, utils


class MailCryptError(ValueError):
    pass


# Bound memory use of password KDFs in each admin worker. Reject instead of
# queueing unbounded work. Front's existing authentication limits also apply.
_unlock_budget = threading.BoundedSemaphore(2)


def document(user):
    record = user.mail_crypt_key
    if record is None:
        return None
    try:
        result = envelope.loads(record.envelope.encode('utf-8'))
        if result['mailbox_id'] != record.mailbox_id:
            raise envelope.KeyringError('Mailbox identity mismatch')
        return result
    except envelope.KeyringError:
        raise MailCryptError('Mailbox encryption metadata is invalid; restore its backup.') from None


def enable(user, password):
    if user.mail_crypt_key is not None:
        raise MailCryptError('Mailbox encryption is already enabled.')
    if not user.check_password(password):
        raise MailCryptError('The current mailbox password is required.')
    mailbox_id = str(uuid.uuid4())
    record = models.MailCryptKey(user=user, mailbox_id=mailbox_id)
    record.envelope = envelope.dumps(envelope.create(mailbox_id, 'password', password))
    models.db.session.add(record)
    return record


def rewrap_password(user, password, unlock_secret, unlock_id='password'):
    result = document(user)
    if result is None:
        return
    if not unlock_secret:
        raise MailCryptError('An existing mailbox unlock credential is required; a password reset cannot recover encrypted mail.')
    try:
        result = envelope.replace_credential(
            result, 'password', password, unlock_id=unlock_id,
            unlock_secret=unlock_secret, mailbox_id=user.mail_crypt_key.mailbox_id,
        )
    except envelope.KeyringError:
        raise MailCryptError('The mailbox unlock credential is invalid.') from None
    if unlock_id == 'recovery':
        del result['slots']['recovery']
    user.mail_crypt_key.envelope = envelope.dumps(result)


def enroll_token(user, token, raw_token, unlock_secret):
    if user.mail_crypt_key is None:
        return
    if token.user.email != user.email or not token.check_password(raw_token):
        raise MailCryptError('The app token does not belong to this mailbox.')
    # Legacy token verification may upgrade its verifier and commit/expire ORM
    # state. Load the envelope afterward so the version counter protects the
    # same document we modify, including during concurrent enrollment.
    result = document(user)
    slot = f'token-{token.id}'
    try:
        operation = envelope.replace_credential if slot in result['slots'] else envelope.add_credential
        result = operation(result, slot, raw_token, unlock_id='password',
                           unlock_secret=unlock_secret, mailbox_id=user.mail_crypt_key.mailbox_id)
    except envelope.KeyringError:
        raise MailCryptError('Could not enroll the app token. Check the mailbox password and available credential slots.') from None
    user.mail_crypt_key.envelope = envelope.dumps(result)


def forget_token(token):
    user = token.user
    result = document(user)
    if result is not None and f'token-{token.id}' in result['slots']:
        result = copy.deepcopy(result)
        del result['slots'][f'token-{token.id}']
        user.mail_crypt_key.envelope = envelope.dumps(result)


def _inline(pem):
    return 'inline:' + base64.b64encode(pem).decode('ascii')


def public_fields(user):
    result = document(user)
    if result is None:
        return {}
    return {
        'crypt_write_algorithm': 'aes-256-gcm-sha256',
        'crypt_global_public_key_file': _inline(envelope.public_pem(result)),
        'crypt_global_private_key': '',
        # Keep the indexes and caches in process memory. Completely disabling
        # cache fields makes delivery logging reopen freshly encrypted mail to
        # read Message-ID/Subject/From, which would require a private key.
        'mail_index_path': 'MEMORY',
        'mail_always_cache_fields': 'hdr.message-id hdr.subject hdr.from size.virtual size.physical',
        'mail_temp_dir': '/usr/run/mailu-crypt-tmp',
        'deliver_log_format': '%{message}',
        'mail_plugins/fts': 'no',
        'mail_plugins/fts_flatcurve': 'no',
    }


def private_fields(user, secret, ip, protocol, auth_port):
    """Release private key only after actual credential verification, never userdb."""
    from mailu.internal.nginx import check_credentials

    result = document(user)
    if result is None:
        return {}
    if protocol not in ('imap', 'pop3', 'submission', 'sieve'):
        raise MailCryptError('A supported mailbox protocol is required.')
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise MailCryptError('A valid client address is required.') from None
    if not _unlock_budget.acquire(blocking=False):
        raise MailCryptError('Mailbox unlock is busy; try again.')
    try:
        # Front has already enforced the webmail-only listener policy. Its
        # Dovecot connection uses port 143 and originates from the trusted net.
        credential_port = auth_port
        if (secret.startswith('crypt-') and protocol == 'imap' and str(auth_port) == '143'
                and utils.is_ip_in_subnet(ip, [net for net in (app.config['SUBNET'], app.config['SUBNET6']) if net])):
            credential_port = '10143'
        if not check_credentials(user, secret, ip, protocol, credential_port):
            raise MailCryptError('Mailbox authentication failed.')
        # A webmail temporary token is not a decryption credential, even if it
        # authenticates. Never try it as a primary password.
        if secret.startswith('token-'):
            raise MailCryptError('Webmail requires a separate mailbox unlock.')
        if secret.startswith('crypt-'):
            record = webmail_record(user, secret)
            if record is None:
                raise MailCryptError('Webmail unlock expired.')
            return private_key_fields(_unwrap(user, record.envelope, secret))
        slot = 'password'
        if utils.is_app_token(secret):
            token = next((token for token in user.tokens if token.check_password(secret)), None)
            if token is None:
                raise MailCryptError('Mailbox authentication failed.')
            slot = f'token-{token.id}'
        try:
            pem = envelope.private_pem(result, slot, secret, mailbox_id=user.mail_crypt_key.mailbox_id)
        except envelope.KeyringError:
            raise MailCryptError('This credential cannot unlock the mailbox; enroll an app token or use the mailbox password.') from None
        return private_key_fields(pem)
    finally:
        _unlock_budget.release()


WEBMAIL_COOKIE = 'mailu_mailbox_unlock'
WEBMAIL_TTL = 3600


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode('utf-8')).hexdigest()


def bounded_kdf(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        if not _unlock_budget.acquire(blocking=False):
            raise MailCryptError('Mailbox unlock is busy; try again.')
        try:
            return function(*args, **kwargs)
        finally:
            _unlock_budget.release()
    return guarded


@bounded_kdf

def wrap(user, secret, *, source=None, unlock_id='password', unlock_secret):
    """Create an independent envelope without consuming password/token slots."""
    try:
        return envelope.dumps(envelope.credential_document(
            source or document(user), 'credential', secret,
            unlock_id=unlock_id, unlock_secret=unlock_secret,
            mailbox_id=user.mail_crypt_key.mailbox_id))
    except envelope.KeyringError:
        raise MailCryptError('The mailbox unlock credential is invalid.') from None


def _unwrap(user, serialized, secret):
    try:
        result = envelope.loads(serialized.encode('utf-8'))
        if result['public_key'] != document(user)['public_key']:
            raise envelope.KeyringError('Mailbox key mismatch')
        return envelope.private_pem(result, 'credential', secret,
                                    mailbox_id=user.mail_crypt_key.mailbox_id)
    except (envelope.KeyringError, AttributeError):
        raise MailCryptError('This credential cannot unlock the mailbox.') from None


def webmail_record(user, secret):
    if not isinstance(secret, str) or not secret.startswith('crypt-') or len(secret) != 49:
        return None
    return models.MailCryptSession.query.filter_by(
        token_hash=digest(secret), user_email=user.email,
    ).filter(models.MailCryptSession.expires_at > int(time.time())).first()


def unlock_webmail(user, password, session_id):
    # An authenticated account session is required by the caller. The password
    # is used for decryption, including after passkey or proxy sign-in.
    secret = 'crypt-' + secrets.token_urlsafe(32)
    wrapped = wrap(user, secret, unlock_secret=password)
    models.MailCryptSession.query.filter_by(user_email=user.email).filter(
        models.MailCryptSession.expires_at <= int(time.time())).delete()
    models.MailCryptSession.query.filter_by(
        user_email=user.email, session_hash=digest(session_id)).delete()
    models.db.session.add(models.MailCryptSession(
        user=user, token_hash=digest(secret), session_hash=digest(session_id),
        expires_at=int(time.time()) + WEBMAIL_TTL, envelope=wrapped))
    models.db.session.commit()
    return secret


def revoke_webmail(user):
    models.MailCryptSession.query.filter_by(user_email=user.email).delete()


@bounded_kdf
def recovery_token(user, password):
    secret = secrets.token_urlsafe(32)
    result = document(user)
    operation = envelope.replace_credential if 'recovery' in result['slots'] else envelope.add_credential
    try:
        result = operation(result, 'recovery', secret, unlock_id='password',
                           unlock_secret=password, mailbox_id=user.mail_crypt_key.mailbox_id)
    except envelope.KeyringError:
        raise MailCryptError('Check the mailbox password and available credential slots.') from None
    user.mail_crypt_key.envelope = envelope.dumps(result)
    return secret


def private_key_fields(pem):
    return {'crypt_global_private_key': 'mailu',
            'crypt_global_private_key/mailu/crypt_private_key_file': _inline(pem)}


unwrap = bounded_kdf(_unwrap)
