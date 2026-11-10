#!/usr/bin/env python3
"""Offline mail-crypt keyring experiment. Never use with production mail yet."""

import argparse
import getpass
import os
import stat
import sys

import keyring


def read_document(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise keyring.KeyringError("Keyring must be a regular file")
        return keyring.loads(source.read(keyring.MAX_DOCUMENT_BYTES + 1))


def write_document(path, document):
    # Each operation writes a NEW file. No in-place mutation or lost updates;
    # the caller must review and deliberately adopt the resulting document.
    data = keyring.dumps(document).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        os.unlink(path)
        raise


def prompt_secret(label, confirm=False):
    # getpass falls back to echoed stdin when no terminal exists. Refuse that
    # path so automation cannot accidentally expose credentials in a transcript.
    if not sys.stdin.isatty():
        raise keyring.KeyringError("Credential entry requires an interactive terminal")
    secret = getpass.getpass(f"{label}: ")
    if confirm and secret != getpass.getpass("Confirm new credential: "):
        raise keyring.KeyringError("New credentials do not match")
    return secret


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create an experimental mailbox keyring")
    init.add_argument("output")
    init.add_argument("--mailbox-id", required=True, help="Stable mailbox UUID, not its address")
    init.add_argument("--credential-id", required=True)
    for name in ("add", "replace", "remove", "public", "unlock"):
        command = commands.add_parser(name)
        command.add_argument("input")
        if name != "public":
            command.add_argument("--mailbox-id", required=True)
            command.add_argument("--unlock-id", required=True)
        if name in ("add", "replace", "remove"):
            command.add_argument("output", help="New path; existing files are never overwritten")
            command.add_argument("--credential-id", required=True)
        if name == "unlock":
            command.add_argument("--export-private-key", required=True, action="store_true",
                                 help="Explicitly permit plaintext PEM on stdout")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            document = keyring.create(args.mailbox_id, args.credential_id,
                                      prompt_secret("New credential", confirm=True))
        else:
            document = read_document(args.input)
            if args.command == "public":
                sys.stdout.buffer.write(keyring.public_pem(document))
                return 0
            secret = prompt_secret("Existing unlock credential")
            unlock_args = dict(unlock_id=args.unlock_id, unlock_secret=secret,
                               mailbox_id=args.mailbox_id)
            if args.command == "unlock":
                if sys.stdout.isatty():
                    raise keyring.KeyringError("Refusing to print a private key to a terminal")
                sys.stdout.buffer.write(keyring.private_pem(
                    document, args.unlock_id, secret, mailbox_id=args.mailbox_id,
                ))
                return 0
            if args.command == "remove":
                document = keyring.remove_credential(document, args.credential_id, **unlock_args)
            else:
                # Authenticate the current slot before asking for a new secret.
                keyring.unlock(document, args.unlock_id, secret, mailbox_id=args.mailbox_id)
                new_secret = prompt_secret("New credential", confirm=True)
                operation = keyring.add_credential if args.command == "add" else keyring.replace_credential
                document = operation(document, args.credential_id, new_secret, **unlock_args)
        write_document(args.output, document)
    except (keyring.KeyringError, OSError, EOFError) as error:
        print(f"mail-crypt: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
