"""Versioned credential envelopes for per-user Dovecot mail-crypt keys.

Kept independent of Flask so the offline key-management tools can use the same
format without initializing an application or database connection.
"""

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


MAX_DOCUMENT_BYTES = 65536
MAX_SLOTS = 16
# A fixed, versioned profile keeps untrusted documents from choosing arbitrary
# memory/CPU costs. A future profile must have a new identifier.
KDF_PROFILE = "argon2id-64m-t3-p4-v1"
_FIELDS = {"version", "mailbox_id", "public_key", "slots"}
_SLOT_FIELDS = {"kdf", "salt", "nonce", "ciphertext"}
_CREDENTIAL_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class KeyringError(ValueError):
    """Malformed envelope, incorrect credential, or failed integrity check."""


def _encode(value):
    return base64.b64encode(value).decode("ascii")


def _decode(value, length=None):
    if not isinstance(value, str):
        raise KeyringError("Invalid envelope encoding")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise KeyringError("Invalid envelope encoding") from None
    if _encode(decoded) != value or (length is not None and len(decoded) != length):
        raise KeyringError("Invalid envelope encoding")
    return decoded


def _credential_id(value):
    if not isinstance(value, str) or not _CREDENTIAL_ID.fullmatch(value):
        raise KeyringError("Credential ID must be 1-64 ASCII letters, digits, '-' or '_'")


def _secret_bytes(secret):
    # Preserve exact Unicode input: authentication must use identical encoding.
    # Never accept password hashes, tokens, or PRF results implicitly.
    try:
        encoded = secret.encode("utf-8") if isinstance(secret, str) else b""
    except UnicodeError:
        raise KeyringError("Credential must be valid UTF-8 text") from None
    if not encoded or len(encoded) > 4096:
        raise KeyringError("Credential must be nonempty UTF-8 text of at most 4096 bytes")
    return encoded


def _derive(secret, salt):
    return Argon2id(
        salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536,
    ).derive(_secret_bytes(secret))


def _public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _aad(document, credential_id):
    # Bind the envelope to the immutable mailbox identity, public key, slot, and
    # format/KDF version. Moving a slot between accounts or IDs must fail.
    return json.dumps([
        "mailu-mail-crypt-credential", document["version"], document["mailbox_id"],
        hashlib.sha256(_decode(document["public_key"])).hexdigest(),
        credential_id, KDF_PROFILE,
    ], separators=(",", ":")).encode("ascii")


def _mailbox_id(mailbox_id):
    try:
        if not isinstance(mailbox_id, str) or str(uuid.UUID(mailbox_id)) != mailbox_id:
            raise ValueError
    except ValueError:
        raise KeyringError("Mailbox identity must be a canonical UUID") from None


def validate(document):
    """Validate structure before any expensive KDF work; never decrypt here."""
    if not isinstance(document, dict) or set(document) != _FIELDS:
        raise KeyringError("Invalid keyring fields")
    if type(document["version"]) is not int or document["version"] != 1:
        raise KeyringError("Unsupported keyring version")
    _mailbox_id(document["mailbox_id"])
    public_der = _decode(document["public_key"], 91)
    try:
        public_key = serialization.load_der_public_key(public_der)
    except ValueError:
        raise KeyringError("Invalid mailbox public key") from None
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise KeyringError("Mailbox public key must use P-256")
    slots = document["slots"]
    if not isinstance(slots, dict) or not 1 <= len(slots) <= MAX_SLOTS:
        raise KeyringError(f"Keyring must contain 1-{MAX_SLOTS} credential slots")
    for credential_id, slot in slots.items():
        _credential_id(credential_id)
        if not isinstance(slot, dict) or set(slot) != _SLOT_FIELDS:
            raise KeyringError("Invalid credential slot fields")
        if slot["kdf"] != KDF_PROFILE:
            raise KeyringError("Unsupported credential KDF profile")
        _decode(slot["salt"], 16)
        _decode(slot["nonce"], 12)
        # P-256 PKCS#8 DER plus a 16-byte GCM tag.
        _decode(slot["ciphertext"], 154)


def _slot(document, credential_id, secret, private_key):
    _credential_id(credential_id)
    salt, nonce = os.urandom(16), os.urandom(12)
    private_der = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {
        "kdf": KDF_PROFILE,
        "salt": _encode(salt),
        "nonce": _encode(nonce),
        "ciphertext": _encode(AESGCM(_derive(secret, salt)).encrypt(
            nonce, private_der, _aad(document, credential_id),
        )),
    }


def create(mailbox_id, credential_id, secret):
    """Create a random P-256 key and a password-wrapped credential slot."""
    _mailbox_id(mailbox_id)
    _credential_id(credential_id)
    private_key = ec.generate_private_key(ec.SECP256R1())
    document = {
        "version": 1, "mailbox_id": mailbox_id,
        "public_key": _encode(_public_bytes(private_key)), "slots": {},
    }
    document["slots"][credential_id] = _slot(document, credential_id, secret, private_key)
    return document


def unlock(document, credential_id, secret, *, mailbox_id):
    """Unlock one slot, bound to the caller's trusted mailbox identity.

    Callers must authenticate and rate-limit separately. This operation is not
    an authentication check and must never be exposed as an unauthenticated API.
    """
    validate(document)
    if document["mailbox_id"] != mailbox_id:
        raise KeyringError("Mailbox identity mismatch")
    _credential_id(credential_id)
    try:
        slot = document["slots"][credential_id]
    except KeyError:
        raise KeyringError("Credential cannot unlock this keyring") from None
    try:
        private_der = AESGCM(_derive(secret, _decode(slot["salt"]))).decrypt(
            _decode(slot["nonce"]), _decode(slot["ciphertext"]), _aad(document, credential_id),
        )
        private_key = serialization.load_der_private_key(private_der, password=None)
    except (InvalidTag, ValueError):
        raise KeyringError("Credential cannot unlock this keyring") from None
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise KeyringError("Invalid mailbox private key")
    if _public_bytes(private_key) != _decode(document["public_key"]):
        raise KeyringError("Mailbox key pair mismatch")
    return private_key


def add_credential(document, credential_id, secret, *, unlock_id, unlock_secret, mailbox_id):
    """Enroll another independent credential without changing the mailbox key."""
    private_key = unlock(document, unlock_id, unlock_secret, mailbox_id=mailbox_id)
    _credential_id(credential_id)
    if credential_id in document["slots"]:
        raise KeyringError("Credential ID already exists")
    if len(document["slots"]) >= MAX_SLOTS:
        raise KeyringError("Credential slot limit reached")
    result = copy.deepcopy(document)
    result["slots"][credential_id] = _slot(result, credential_id, secret, private_key)
    return result


def replace_credential(document, credential_id, secret, *, unlock_id, unlock_secret, mailbox_id):
    """Rewrap a slot after unlocking, e.g. for a user-initiated password change."""
    private_key = unlock(document, unlock_id, unlock_secret, mailbox_id=mailbox_id)
    _credential_id(credential_id)
    if credential_id not in document["slots"]:
        raise KeyringError("Credential ID does not exist")
    result = copy.deepcopy(document)
    result["slots"][credential_id] = _slot(result, credential_id, secret, private_key)
    return result


def remove_credential(document, credential_id, *, unlock_id, unlock_secret, mailbox_id):
    """Remove a slot. Revocation also requires invalidating live sessions."""
    unlock(document, unlock_id, unlock_secret, mailbox_id=mailbox_id)
    _credential_id(credential_id)
    if credential_id not in document["slots"]:
        raise KeyringError("Credential ID does not exist")
    if len(document["slots"]) == 1:
        raise KeyringError("Cannot remove the last credential slot")
    result = copy.deepcopy(document)
    del result["slots"][credential_id]
    return result


def public_pem(document):
    """Return only the public encryption key; suitable for locked delivery."""
    validate(document)
    return serialization.load_der_public_key(_decode(document["public_key"])).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_pem(document, credential_id, secret, *, mailbox_id):
    """Export plaintext PKCS#8 PEM for a short-lived, authenticated consumer."""
    return unlock(document, credential_id, secret, mailbox_id=mailbox_id).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def dumps(document):
    validate(document)
    return json.dumps(document, sort_keys=True, indent=2) + "\n"


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise KeyringError("Duplicate keyring JSON field")
        result[key] = value
    return result


def loads(data):
    if not isinstance(data, bytes) or len(data) > MAX_DOCUMENT_BYTES:
        raise KeyringError("Keyring document must be at most 64 KiB")
    try:
        document = json.loads(data, object_pairs_hook=_unique_fields)
    except (ValueError, UnicodeError, RecursionError):
        raise KeyringError("Invalid keyring JSON") from None
    validate(document)
    return document
