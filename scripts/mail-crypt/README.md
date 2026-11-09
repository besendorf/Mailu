# Per-user mail-crypt keyring experiment

An offline prototype for [Mailu #1040](https://github.com/Mailu/Mailu/issues/1040).
It explores credential-independent mailbox keys: a random P-256 private key is
wrapped separately for each enrolled password or app credential. Changing a
credential rewraps the same key rather than re-encrypting all messages.

**This does not enable mail encryption in Mailu. Do not use the prototype with
production mail.** It has no database integration, authenticated unlock endpoint,
Dovecot configuration, live-session revocation, or mail migration. Its storage
format is experimental. See the [integration design](../../design/per-user-mail-crypt.md)
for the remaining work and security boundaries.

## Run the experiment

Use Python 3.9+ and `cryptography` 44+ with Argon2id support. Install the isolated
dependencies in a virtual environment, from this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Create a disposable mailbox keyring. The UUID represents a stable mailbox
identity, independent of an address that could be renamed or reused. In a real
integration this must come from the authenticated account record.

```sh
.venv/bin/python manage.py init envelope.json \
  --mailbox-id 308ebd91-d9b4-4fd6-9d5a-730968f1ae59 \
  --credential-id password
```

All secrets are entered at terminal prompts, never as command-line arguments or
environment variables. Each write creates a new file with mode `0600` and refuses
to overwrite an existing path. The files contain the public key and encrypted
private-key slots. Back them up along with the credentials needed to unlock them.

Enroll an independent app credential while an existing credential can unlock
the mailbox key:

```sh
.venv/bin/python manage.py add envelope.json enrolled.json \
  --mailbox-id 308ebd91-d9b4-4fd6-9d5a-730968f1ae59 \
  --unlock-id password --credential-id app-phone
```

`replace` takes the same arguments and replaces an existing slot; `remove`
removes the named slot, unless it is the last one. Every mutation requires a
working unlock credential. Review and adopt each new file deliberately; these
commands do not modify Mailu accounts, app tokens, or sessions. Old envelope
copies remain usable with old credentials. Removing a slot cannot revoke a
private key already obtained by a client or an attacker.

Inspect the public key without unlocking:

```sh
.venv/bin/python manage.py public enrolled.json
```

Check interoperability with OpenSSL, without writing the private key to disk:

```sh
.venv/bin/python manage.py unlock enrolled.json \
  --mailbox-id 308ebd91-d9b4-4fd6-9d5a-730968f1ae59 \
  --unlock-id password --export-private-key | openssl pkey -pubout
```

The last command deliberately exports plaintext PKCS#8 PEM through stdout;
connect it only to a trusted local consumer. The tool refuses to print a private
key directly to a terminal. It cannot prevent a shell, pipe consumer, debugger,
swap, crash dump, or redirected output from retaining plaintext.

## Format and boundaries

- Version 1 uses P-256 PKCS#8 private keys and SPKI public keys, encoded as DER
  internally and exported as PEM for OpenSSL/Dovecot experiments.
- Each slot uses Argon2id (64 MiB, 3 iterations, 4 lanes, 16-byte random salt) to
  derive a 256-bit AES-GCM key, with a fresh random 12-byte nonce.
- Associated data binds the format version, stable mailbox UUID, public-key
  digest, credential ID, and KDF profile. Slot swaps and metadata tampering fail
  authentication. The public key itself still needs trusted storage: an attacker
  able to replace a delivery public key can redirect encryption of future mail.
- Only the named slot is tried. Input limits and a fixed KDF profile bound work
  per attempt; a network service would still need authentication, rate limits,
  and concurrency limits before attempting unlock.
- Password/app-credential enrollment is demonstrated. OAuth tokens and passkey
  assertions are **not** decryption secrets. A WebAuthn PRF or an explicit
  separate unlock step needs a different, reviewed integration.
- These checks provide neither secure memory erasure in Python nor an
  end-to-end-encryption guarantee against the running server administrator.

The tests exercise actual Argon2id/AES-GCM, credential lifecycle, tampering,
identity/slot swapping, malformed JSON, file handling, and PEM interoperability.
They do **not** establish Dovecot runtime compatibility or encrypted delivery.
