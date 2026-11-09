"""Per-mailbox mail-crypt provisioning and authenticated key release.

Only credential-encrypted private keys are persisted. No unlock cache, recovery
master key, or token-derived server-side fallback is used.
"""

import base64
import copy
import ipaddress
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
    user.mail_crypt_key.envelope = envelope.dumps(result)


def enroll_token(user, token, raw_token, unlock_secret):
    result = document(user)
    if result is None:
        return
    if token.user.email != user.email or not token.check_password(raw_token):
        raise MailCryptError('The app token does not belong to this mailbox.')
    slot = f'token-{token.id}'
    try:
        operation = envelope.replace_credential if slot in result['slots'] else envelope.add_credential
        result = operation(result, slot, raw_token, unlock_id='password',
                           unlock_secret=unlock_secret, mailbox_id=user.mail_crypt_key.mailbox_id)
    except envelope.KeyringError:
        raise MailCryptError('Could not enroll the app token. Check the mailbox password and the 15-token limit.') from None
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
        if not check_credentials(user, secret, ip, protocol, auth_port):
            raise MailCryptError('Mailbox authentication failed.')
        # A webmail temporary token is not a decryption credential, even if it
        # authenticates. Never try it as a primary password.
        if secret.startswith('token-'):
            raise MailCryptError('Webmail requires a separate mailbox unlock.')
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
        return {
            'crypt_global_private_key': 'mailu',
            'crypt_global_private_key/mailu/crypt_private_key_file': _inline(pem),
        }
    finally:
        _unlock_budget.release()
