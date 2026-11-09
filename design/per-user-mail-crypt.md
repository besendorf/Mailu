# Per-user mailbox encryption

This branch implements opt-in encryption for newly written mail, plus an offline
migration tool for existing Maildirs. It addresses Mailu/Mailu#1040 using Dovecot
**global-key mode scoped per user through userdb**, rather than per-folder keys.
See [operator instructions](../docs/mail-crypt.rst) for activation and recovery.

## Key hierarchy and authentication

Each mailbox has a random P-256 key pair and an immutable UUID. The public key is
available to delivery; private keys are stored only as credential envelopes.
Each password or enrolled app token wraps the same PKCS#8 key with a separate
Argon2id-derived AES-256-GCM key. Slot identity, mailbox UUID, public-key digest
and format/KDF version are authenticated as associated data. Password changes
rewrap the key; they do not rotate it or rewrite mail.

`MailCryptKey` has an ORM version counter to reject concurrent, conflicting
credential changes. Password verifier changes and envelope rewrapping commit in
one transaction. Direct ORM password assignment, raw-hash imports and reset
links are blocked for encrypted mailboxes. An enrolled app token can recover the
primary-password slot through the operator CLI. Losing every unlock credential
and usable backup makes the mailbox irrecoverable.

Front authentication still enforces existing protocol/account/IP policy. For an
encrypted account, the Dovecot Lua passdb independently validates the supplied
password or app token before unlocking its slot and returning prefetched
`userdb_` settings. A prefetch userdb precedes the existing Lua fallback. Ordinary
userdb, iteration and LMTP requests return only the public key and never unlock.
Private responses have `Cache-Control: no-store`. Malformed key records cause
temporary lookup failures, not an unknown-recipient bounce or plaintext fallback.

OAuth tokens, WebAuthn assertions and derived webmail session tokens are not
unlock credentials. Encrypted accounts reject OAuth mail introspection and
webmail SSO. Passkeys still work for account administration; encrypted mailbox
access uses an enrolled app token. This is an explicit restriction, not an
implementation of WebAuthn PRF or an in-memory unlock broker.

## Dovecot storage and delivery

The mail-crypt plugin is available globally, with encrypted writes disabled by
default. Per-user settings enable AES-256-GCM writes, set a public key and clear
inherited private keys. Authenticated passdb prefetch supplies the private-key
named filter and its inline PEM. Unencrypted users keep their existing settings.

Encrypted accounts use `mail_index_path = MEMORY`; FTS is disabled. This keeps
header/body caches off the persistent mailbox volume while allowing delivery
logging to retrieve cached Message-ID/Subject/From from the incoming message.
Completely disabling all caches makes first LDA/Sieve delivery reopen encrypted
temporary mail to obtain logging headers. Always caching the required fields
in process memory avoids requiring the private key during delivery. Maildir
UID/control files, message flags and sizes remain persistent metadata.

Seekable decrypted/compressed streams may spill into temporary files. Their
`mail_temp_dir` is inside `/mail/usr`, whose tmpfs mount is checked by startup.
A root-owned sticky directory and Dovecot's private temporary files isolate the
per-mailbox UIDs. These caches/tempfiles are not included in mailbox-volume
backups. Operators must also protect host swap and crash dumps if the threat
model includes recovery of RAM contents from storage.

Changing account settings does not change an already running mail process.
Operators must stop mailbox access/delivery for activation and migration and
restart IMAP afterward. Password changes, token deletion and web logout block
new authentication; existing mail sessions must be disconnected separately.
The implementation does not promise immediate key erasure on browser logout.

## Existing mail and recovery

`encrypt_maildir.py` uses Dovecot fs-crypt with the mailbox public key to produce
a separate encrypted home. It preserves Maildir names, UID/control files,
flags and timestamps, omits stale disk indexes/caches and pending Maildir temp
files, rejects unsafe paths/symlinks, detects source changes and writes a
completion manifest. It never swaps directories or removes the source. The
operator verifies decryption/UIDs before a directory swap while services remain
offline. Already encrypted files are retained; this tool does not rotate keys.

The CLI exports encrypted envelopes and the public PEM, shows the stable
identity/home, and restores an original envelope only after a supplied backup
credential unlocks it under the operator's expected mailbox UUID. Restore does
not reset authentication credentials. Database downgrades refuse to drop a
nonempty key table.

## Security boundary and validation

This protects encrypted message files in an offline mailbox-volume copy/backup
when no usable credential/private key is captured. It does not protect against
an active administrator, plaintext SMTP queues, external logs, quarantine,
forwarded copies, historical plaintext backups, weak-password guessing or live
memory compromise. It is not end-to-end encryption or a legal guarantee.

Tests cover real Argon2id/AES-GCM, PEM interoperability, authenticated key release,
credential/IP policy, lifecycle/rollback/concurrency, reset/import guards,
Dovecot public-only writes, authenticated reads, compression, Sieve plus quota,
missing-key failure and offline migration preserving UIDs/flags/source data.
The dedicated CI workflow also runs a rootless master-daemon test for real
LMTP delivery and IMAP authentication through Mailu's Lua passdb/userdb.
