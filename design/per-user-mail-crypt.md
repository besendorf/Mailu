# Proposal: opt-in per-user encryption at rest

Status: design and offline key-management prototype, **not an enabled Mailu
feature**. Tracks [#1040](https://github.com/Mailu/Mailu/issues/1040), including
the [authentication concerns](https://github.com/Mailu/Mailu/issues/1040#issuecomment-6745723340).

## Storage mode and intended benefit

Use Dovecot's **global-key storage mode with per-user keys supplied through
userdb**. “Global” describes how the plugin obtains keys, not a requirement that
every mailbox share one key. Dovecot explicitly documents per-user/group scopes
for global keys. This avoids relying on the per-folder key mode that its
[mail-crypt documentation](https://doc.dovecot.org/main/core/plugins/mail_crypt.html)
currently labels unsuitable for production. Exact userdb field names, named
filters, and PEM handling must be validated against Mailu's packaged Dovecot
2.4 release before enabling anything.

Generate a random asymmetric key pair for each mailbox. Keep the public key
available for delivery; store the private key only in credential-encrypted
envelopes. Give each supported credential a separate envelope for the same
private key. This decouples mailbox contents from individual login methods.
Never derive a mailbox private key directly from a password, reuse a stored
password hash as a wrapping secret, or keep a server-wide fallback unlock key.

The intended benefit is confidentiality of encrypted message files in a cold
backup or offline mailbox-volume seizure, provided the attacker lacks a usable
credential, private-key copy, or captured process memory. Weak passwords remain
subject to offline guessing. Plaintext SMTP queues, logs, indexes, message caches,
FTS/attachment indexes, quarantine and backups need separate consideration.
Mail-crypt alone does not establish confidentiality for those artifacts.

This is not end-to-end encryption. The server handles plaintext during delivery
and authenticated reads. A privileged operator can capture credentials/keys or
alter future server/client responses. An active session may retain the key after
browser logout. No claim about subpoena resistance follows from this feature.

## Existing Mailu integration points

At the initial implementation base `e1062684d63f7751a654008fd028db108695804d`:

- `core/admin/mailu/internal/nginx.py` authenticates the front proxy's users.
  Temporary webmail tokens and application tokens are distinct credential paths.
- `core/admin/mailu/internal/views/dovecot.py` returns trusted-proxy passdb
  results (`nopassword`) and passwordless userdb records, including LMTP lookups.
- `core/dovecot/conf/login.lua` passes request credentials to those endpoints.
  The existence of a password header at this hop is not proof that it is the
  user's primary password.
- `core/dovecot/conf/dovecot.conf` configures Lua passdb and userdb alongside a
  separate OAuth introspection path, mailbox chroots, indexes and FTS.
- `core/admin/mailu/models.py::User.set_password()` serves several reset/change
  paths. It currently has no old-password argument or encrypted-key transaction.

Returning a decrypted key from ordinary userdb would expose it to passwordless
LMTP/background jobs. Adding `%{password}` to the current passdb would mishandle
app/temporary/OAuth credentials. Neither is an acceptable integration shortcut.

## Credential policy

Authentication and unlocking are separate operations. A successful account login
does not imply that a mailbox decryption secret is available.

| Credential | Proposed mailbox unlock behavior |
| --- | --- |
| Primary password | Authenticate first, then use its slot to unlock the random mailbox key. |
| App token | Enroll a slot when the token is created while the mailbox is unlocked. Use the token's actual secret, not its stored verifier. Existing tokens need explicit enrollment or replacement. |
| Passkey with WebAuthn PRF | Requires client/browser PRF support, explicit enrollment, and a separate reviewed key-derivation/wrapping path. The passkey signature is not key material. |
| Passkey without PRF | Account login can succeed, but mailbox access needs a separate unlock credential. |
| OAuth access/refresh token | Authorizes account access only. Never derive a durable wrapping key from a rotating token. Require a separately established, expiring unlock session or an explicit mailbox-unlock step. |
| Webmail temporary token | May refer to an already unlocked mailbox session; cannot unlock from its existing server-derived token alone. |
| Recovery credential | Optional explicit user-held, high-entropy credential slot. No implicit administrator recovery. |

Users must see which login methods can read an encrypted mailbox before opting
in. Unsupported methods must fail with an explicit unlock requirement, rather
than enabling plaintext storage or obtaining a server-held fallback secret.

The prototype implements only password-style envelopes and lifecycle operations.
It does not implement the passkey, OAuth, recovery UI, or session mechanisms above.

## Delivery, access and background processing

1. Enrollment must allocate an immutable mailbox identity and key pair before
   any encrypted delivery, storing the public key and envelopes atomically.
   Address rename/reuse must not reuse another mailbox's identity or keys.
2. LMTP receives only the recipient's public key. A locked mailbox must accept
   ordinary new messages without a private key or logged-in user. A missing key
   or unusable encryption configuration must temporarily fail delivery; no
   automatic generation of a replacement key or plaintext fallback is allowed.
3. Authenticated IMAP/POP access obtains the private key only after a supported
   credential unlocks a slot. The key must be passed to that user's process via
   a reviewed per-login mechanism; never by a public API, URL, command line,
   persistent file or global environment variable.
4. A locked mailbox must not expose its private key to iteration, `doveadm`,
   indexing, OAuth introspection, or passwordless userdb lookups. Trusted mailbox
   identity and credential ID must come from authenticated records, not a
   submitted envelope.
5. Sieve scripts that read old mail, duplicate detection, spam training,
   reindexing, BURL/URLAUTH, forwarding, shared mailboxes, FTS, and background
   migration may need read access. Test each explicitly; postpone incompatible
   operations while locked or block enrollment for that feature combination.
   Public-key-only delivery must be demonstrated with the actual Mailu Sieve
   pipeline, not assumed from the encryption primitive.

Any in-memory unlock broker is a separate security-sensitive component. Define
ownership, per-mailbox authorization, timeouts, maximum lifetime, crash/restart
behavior, lock operation, and revocation before introducing one. Redis persistence
and existing web sessions are not appropriate default plaintext-key stores.
Python cannot promise zeroization; private-key handling and dump/swap exposure
need an explicit implementation decision.

## Password changes, revocation and recovery

A normal password change must unlock the existing mailbox key using an enrolled
credential and rewrap it under the new password. Commit the new password verifier
and envelope in the same database transaction. Cover UI, CLI, API, raw-hash import,
administrator reset, and external authentication paths. If rewrapping cannot be
done, preserve the old envelope and require recovery; do not silently generate
a new mailbox key, discard the old one, or report that mail access was preserved.

Administrative password reset cannot decrypt old mail by itself. Explain that
before enrollment and at reset time. Enrollment should require either an
independently verified recovery credential or an explicit acknowledgement of
irrecoverable loss if all unlock credentials are lost. Test backup restoration
before enabling encrypted writes.

Removing an app-token slot must also revoke authentication and terminate its
unlocked sessions. Revoke webmail unlock references and Dovecot processes on
explicit mailbox lock. Browser logout alone is insufficient. Keys already copied
and envelopes retained in old backups cannot be revoked retroactively. True
mailbox-key rotation needs its own migration and retention design; it is not
the same operation as replacing a password slot.

## Migration and rollout gates

The offline prototype in [`scripts/mail-crypt`](../scripts/mail-crypt/README.md)
tests envelope operations and PEM output without touching Mailu's defaults or
data. Production integration remains pending:

- Add reviewed, versioned database storage for keys and credential slots, plus
  opt-in/enrollment UI and transactional lifecycle changes.
- Validate generated configuration with the packaged `doveconf`; prove distinct
  per-user global keys and private-key-free LMTP against the actual Dovecot image.
- Add authenticated, bounded unlock handling for primary passwords and enrolled
  app tokens. Specify passkey/OAuth policy and webmail behavior before opt-in.
- Prove passwordless/background paths never receive private keys. Add tests for
  invalid credentials, cross-user requests, slot swaps, concurrent enrollment,
  all reset/import paths, rate/concurrency limits, lock and session revocation.
- Test delivery while locked with Sieve, IMAP append/read/copy, POP, compression,
  FTS enabled/disabled, BURL, forwarding, and a restart with no unlocked sessions.
- Demonstrate that raw message files are encrypted and that they decrypt only
  with the intended key. Examine indexes/caches/queues separately; disable or
  protect plaintext-derived artifacts consistent with the advertised guarantee.
- Implement an explicit migration for existing plaintext mail, including copies,
  historical keys, quota, free-space, rollback and interrupted migration tests.
  Enabling encryption for new writes does not encrypt old files automatically.
- Exercise loss/recovery and backup/restore with a disposable installation;
  document which keys, metadata and credential slots backups must retain.

Do not add a production `MAIL_CRYPT` toggle until these gates are met. This work
does not close #1040 and is intended for design review and further development
in the fork before proposing an upstream implementation.
