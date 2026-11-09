#!/usr/bin/env python3
"""Build an encrypted copy of an OFFLINE mailbox home, preserving the source.

Uses Dovecot's fs-crypt writer and a public key only. Never swaps directories,
deletes the original, or writes a private key to a file/command line.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


MAGIC = b'CRYPTED\x03\x07'
COMPLETE = '.mailu-encryption-complete.json'


def inventory(source):
    result = {}
    for root, directories, files in os.walk(source, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise ValueError(f'Unexpected special file: {path}')
            if path.is_symlink() and not path.resolve().is_relative_to(source):
                raise ValueError(f'Symlink leaves the mailbox home: {path}')
            result[str(path.relative_to(source))] = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode)
    return result


def _attributes(source, target):
    info = source.stat()
    current = target.stat()
    if (info.st_uid, info.st_gid) != (current.st_uid, current.st_gid):
        os.chown(target, info.st_uid, info.st_gid)
    shutil.copystat(source, target)


def migrate(source, destination, public_key, *, config='/etc/dovecot/dovecot.conf', doveadm=('doveadm',)):
    source = Path(source).resolve(strict=True)
    requested_destination = Path(destination).absolute()
    if requested_destination.exists() or requested_destination.is_symlink():
        raise ValueError('Destination must not exist; an incomplete copy must never replace the source.')
    destination = requested_destination.resolve()
    public_key = Path(public_key).resolve(strict=True)
    if not source.is_dir() or destination.is_relative_to(source):
        raise ValueError('Use a mailbox home and a separate, new destination directory.')
    before = inventory(source)
    destination.mkdir(mode=0o700)
    encrypted = copied = 0
    # Root directory attributes are applied only after the final manifest, so
    # a failed copy remains an obvious, incomplete destination.
    for root, directories, files in os.walk(source, followlinks=False):
        relative = Path(root).relative_to(source)
        target_root = destination / relative
        target_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        in_maildir = Path(root).name in ('cur', 'new')
        for name in list(directories):
            path = Path(root) / name
            if name in ('indexes', 'fts-flatcurve', 'xapian-indexes') or (
                name == 'tmp' and {'cur', 'new'}.issubset(set(directories))
            ):
                directories.remove(name)
                continue
            if path.is_symlink():
                directories.remove(name)
                raise ValueError(f'Directory symlink needs manual review: {path}')
        for name in files:
            original = Path(root) / name
            target = target_root / name
            if not in_maildir and ((name.startswith('dovecot') and '.index' in name) or name == COMPLETE):
                continue
            if original.is_symlink():
                if in_maildir:
                    raise ValueError(f'Maildir message must be a regular file: {original}')
                link_target = destination / original.resolve().relative_to(source)
                target.symlink_to(os.path.relpath(link_target, target.parent))
                continue
            with original.open('rb') as handle:
                already_encrypted = handle.read(len(MAGIC)) == MAGIC
            if in_maildir and not already_encrypted:
                command = list(doveadm) + [
                    '-c', config, '-o', 'fs=crypt,posix',
                    '-o', 'fs/crypt/fs_driver=crypt', '-o', 'fs/posix/fs_driver=posix',
                    '-o', 'crypt_write_algorithm=aes-256-gcm-sha256',
                    '-o', f'crypt_global_public_key_file={public_key}',
                    '-o', 'crypt_global_private_key=',
                    'fs', 'put', '', str(original), str(target),
                ]
                subprocess.run(command, check=True, capture_output=True)
                with target.open('rb') as handle:
                    if handle.read(len(MAGIC)) != MAGIC:
                        raise ValueError('Dovecot did not produce an encrypted message.')
                encrypted += 1
            else:
                shutil.copyfile(original, target)
                copied += int(in_maildir)
            _attributes(original, target)
            with target.open('rb') as handle:
                os.fsync(handle.fileno())
    if inventory(source) != before:
        raise ValueError('Source changed during migration. Keep the source and discard this incomplete destination.')
    manifest = {
        'version': 1, 'encrypted_messages': encrypted, 'copied_encrypted_messages': copied,
        'public_key_sha256': hashlib.sha256(public_key.read_bytes()).hexdigest(),
    }
    for root, directories, _files in os.walk(source, topdown=False):
        target = destination / Path(root).relative_to(source)
        if target.exists() and not target.is_symlink():
            _attributes(Path(root), target)
            descriptor = os.open(target, os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    marker = destination / COMPLETE
    marker.write_text(json.dumps(manifest, sort_keys=True) + '\n')
    marker.chmod(0o600)
    with marker.open('rb') as handle:
        os.fsync(handle.fileno())
    descriptor = os.open(destination, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Offline mailbox HOME, containing mail/, sieve/, metadata/')
    parser.add_argument('destination', help='New, separate mailbox home; source is retained')
    parser.add_argument('public_key', help='PEM exported by flask mailu mail-crypt public-key')
    parser.add_argument('--offline', required=True, action='store_true', help='Confirm all access and delivery to the source is stopped')
    parser.add_argument('--config', default='/etc/dovecot/dovecot.conf')
    args = parser.parse_args()
    try:
        result = migrate(args.source, args.destination, args.public_key, config=args.config)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Migration failed; source retained and destination must not be used: {error}\n')
    print(json.dumps(result))
    print('Source retained. Verify message reads with the matching unlock credential before an offline directory swap.')


if __name__ == '__main__':
    main()
