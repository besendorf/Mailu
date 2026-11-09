Per-user mailbox encryption
===========================

Mailbox encryption is opt-in. Each account has a separate random encryption
key; a password or explicitly enrolled app token unlocks its private key.
Delivery uses only the public key, including while the user is logged out.
This uses Dovecot global-key mode with per-user scope, not per-folder keys.

Supported access and limitations
-------------------------------

* IMAP, POP3, submission and ManageSieve use an enrolled app token. Primary
  passwords also work where the existing ``AUTH_REQUIRE_TOKENS`` policy permits
  them. That policy is not weakened by enabling encryption.
* Webmail SSO and OAuth mail access are unavailable for encrypted accounts.
  Passkeys can still sign in to account administration. An OAuth token or
  passkey assertion is not treated as a decryption secret.
* Full-text indexing is disabled. Mail indexes/header caches are kept in
  process memory, with a performance cost when reconnecting to large mailboxes.
  Seekable plaintext temporary streams use the IMAP container's existing tmpfs.
* Encryption protects message files in a mailbox-volume backup or offline
  copy. UID/control files, flags, folder names and message sizes remain metadata.
  SMTP queues, quarantine, logs, forwarded mail, old plaintext backups and live
  server memory need separate protection. Host swap and crash dumps can retain
  memory contents. This is not end-to-end encryption against the server operator.
* Lost encryption credentials cannot be replaced by an administrative password
  reset. Keep an independent enrolled app token and encrypted key backups.

Activation
----------

Deploy the updated admin **and** IMAP images, including the database migration.
Take a database/mailbox backup first. Stop IMAP access and delivery while
provisioning, so existing processes cannot keep writing with old plaintext
settings. Keep admin available for the following commands. Do not restart old
admin versions against the upgraded schema.

The account UI's **Mailbox encryption** page explains the restrictions and
allows a password-authenticated account to request the same per-user setting.
An operator must still disconnect/restart existing mail processes before
encryption can be relied on.

Alternatively, run::

    docker compose exec admin flask mailu mail-crypt enable alice@example.org --acknowledge-limitations
    docker compose exec admin flask mailu mail-crypt status alice@example.org

The current password is entered at a hidden prompt. Export the encrypted key
envelopes and public PEM before migrating data::

    umask 077
    docker compose exec -T admin flask mailu mail-crypt export alice@example.org > alice-envelopes.json
    docker compose exec -T admin flask mailu mail-crypt public-key alice@example.org > alice-public.pem

Record the mailbox UUID and home shown by ``status`` alongside the backup.
The normal configuration export does not replace a database/key-envelope backup.
Both the message files and their matching original encryption keys are needed
for recovery. Never generate a new key to replace a lost original key.

Restart IMAP after provisioning. Existing mail processes cache userdb settings;
enabling the database record alone cannot change already established sessions.
On an existing mailbox, old files remain plaintext until explicitly migrated.

App tokens and password changes
-------------------------------

When creating an authentication token in the account UI, supply the mailbox
encryption password. The same private key is wrapped under that token without
storing the password. Existing tokens must be enrolled or replaced. To enroll
an existing token, use its numeric token ID::

    docker compose exec admin flask mailu mail-crypt enroll-token alice@example.org 7

Both the current encryption password and existing app token are entered at
hidden prompts. The limit is 15 enrolled app-token slots plus the password slot.
Deleting a token removes its current slot and prevents future authentication.
Disconnect its live mail sessions separately: deletion or browser logout does
not erase keys from already established sessions, copied keys or old backups.

A normal password change in account administration rewraps the existing key
atomically with the new password verifier. To change it through the operator
CLI, or recover using another enrolled credential::

    docker compose exec admin flask mailu mail-crypt change-password alice@example.org
    docker compose exec admin flask mailu mail-crypt change-password alice@example.org --unlock-id token-7

The second form accepts the enrolled token at the unlock prompt. Neither form
rotates the mailbox key. Administrative reset links and raw password-hash
imports are rejected for encrypted accounts because they cannot rewrap that key.
The user API accepts ``mailbox_unlock_password`` alongside ``raw_password``;
token creation accepts ``mailbox_password``. Unlock secrets are never returned.

Migrating existing mail
----------------------

Stop **all** mailbox access and delivery. The migration must see an offline,
unchanging mailbox. Export keys first, then stop the stack if needed. Keep the
original database and source mailbox backup until recovery is verified.

Use the exact source home shown by ``mail-crypt status``. In the following
example, replace ``SOURCE_HOME`` and ``NEW_HOME`` with separate absolute paths
inside the mounted mail volume; the destination must not exist::

    docker compose run --rm --no-deps --entrypoint python3 \
      -v "$PWD/alice-public.pem:/tmp/mailbox-public.pem:ro" imap \
      /encrypt_maildir.py SOURCE_HOME NEW_HOME /tmp/mailbox-public.pem --offline

The tool writes an encrypted copy with Dovecot fs-crypt using only the public
key. Maildir filenames, UIDs, flags, control files and timestamps are preserved.
Stale disk indexes/caches and pending Maildir temporary files are omitted.
Internal Sieve symlinks are preserved; escaping/directory symlinks need review.
Existing encrypted messages are copied, so this is not a key-rotation tool.

On failure, retain the source and do not use the incomplete destination. The
tool never swaps paths or deletes source data. A successful copy has a
``.mailu-encryption-complete.json`` manifest. While services remain offline,
verify the matching credential can read the copied mail, including representative
attachments, message counts, UIDs and flags. Only then swap the source home and
new home, keeping the original as an explicitly plaintext backup. Restore the
original path if verification fails. Remove obsolete plaintext backups according
to your backup policy; this tool does not securely erase storage blocks.

Restoring key envelopes
----------------------

Restore a consistent database/mailbox backup together. For a missing or damaged
key record, the CLI can restore the original envelope backup after verifying
its unlock credential and the mailbox UUID from the trusted backup inventory::

    docker compose cp alice-envelopes.json admin:/tmp/alice-envelopes.json
    docker compose exec admin flask mailu mail-crypt restore alice@example.org \
      /tmp/alice-envelopes.json --mailbox-id ORIGINAL_MAILBOX_UUID

Restore leaves authentication credentials unchanged. If the backup was wrapped
under an older password, use ``change-password`` to rewrap it under a new one.
Do not import another mailbox's key or create a replacement key pair. A schema
downgrade refuses to drop a nonempty encryption-key table.

Development validation
----------------------

The ``Mailbox encryption`` workflow runs the application tests, real Dovecot
2.4 storage/delivery tests and a rootless master-daemon LMTP/IMAP test through
Mailu's Lua passdb and userdb. Runtime tests can be run locally by setting the
``DOVECOT_TEST_*`` paths documented in
``tests/anonmail/test_mail_crypt_dovecot.py``. Hosts prohibiting Unix-domain
sockets skip the full daemon test; storage/Sieve/migration tests still run.
